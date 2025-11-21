"""
Copyright Meower Media 2024.


This filter includes the following:
- Malware detection using ClamAV
- NSFW detection using Falconsai/nsfw_image_detection and KoalaAI/Text-Moderation from Hugging Face


A file detected as malware will be flagged and blocked.


A file detected as likely NSFW will be flagged. The "likely" NSFW threshold is currently at 75%.
If the post the file is in gets reported by another user or the text of the post contains inappropriate content, the file will be blocked.


If a user accumulates 3 or more unique flags within 24 hours, they will be automatically banned.
"""


from dotenv import load_dotenv
load_dotenv()


import asyncio, os, redis.asyncio as redis, pymongo, minio, msgpack, json, clamd, time
from typing import TypedDict, Literal, Optional
from enum import Enum
from PIL import Image
from transformers import pipeline

NSFW_SCORE_THRESHOLD = 0.8

class EventType(Enum):
    NEW_UPLOAD = 0
    NEW_POST = 1

class Event(TypedDict):
    type: EventType
    username: str
    file_bucket: Literal["icons", "emojis", "stickers", "attachments"]
    file_hashes: list[str]
    post_id: Optional[str]
    post_content: Optional[str]

class FileClassification(TypedDict):
    file_hash: str
    malware: bool
    nsfw_score: float

async def main():
    # Connect to Redis and initialise pub/sub
    r = redis.from_url(os.environ["REDIS_URI"])
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    await pubsub.subscribe("automod:files")

    # Connect to MongoDB
    db = pymongo.MongoClient(os.environ["MONGO_URI"])[os.environ["MONGO_DB"]]

    # Connect to MinIO
    s3 = minio.Minio(
        os.environ["S3_ENDPOINT"],
        access_key=os.environ["S3_ACCESS"],
        secret_key=os.environ["S3_SECRET"],
        secure=os.environ["S3_SECURE"] == "1"
    )

    # Connect to ClamAV daemon
    cd = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310)
    #cd = clamd.ClamdUnixSocket(path=os.environ["CLAMD_SOCK"])

    # Initialise Hugging Face classifiers
    nsfw_image_detection = pipeline("image-classification", model="Falconsai/nsfw_image_detection")
    text_classifier = pipeline("text-classification", model="KoalaAI/Text-Moderation")

    async def get_file_classification(bucket: str, file_hash: str) -> FileClassification:
        # Cached classification
        classification = await r.get(f"automod:files:classification:{file_hash}")
        if classification:
            classification: FileClassification = msgpack.unpackb(classification)
            return classification

        # Get file mime
        mime: str = db.files.find_one({"hash": file_hash})["mime"]

        # Create directory
        fp = os.environ["TEMP_DIR"] + "/" + file_hash

        # Download file to directory
        if bucket == "attachments" and mime.startswith("video/"):  # download thumbnail for attachment videos
            s3.fget_object(os.environ["S3_BUCKET"], f"{bucket}/{file_hash}_thumbnail", fp)
        else:
            s3.fget_object(os.environ["S3_BUCKET"], f"{bucket}/{file_hash}", fp)

        # Scan with ClamAV
        clam_result, _ = list(cd.scan(fp).values())[0]

        # Scan for NSFW if file is an image or video
        nsfw_score = 0
        if mime.startswith("image/") or mime.startswith("video/"):
            for item in nsfw_image_detection(Image.open(fp)):
                if item["label"] == "nsfw":
                    nsfw_score = item["score"]

        # Remove file
        os.remove(fp)

        # Create and cache classification for 24 hours
        classification: FileClassification = {
            "file_hash": file_hash,
            "malware": clam_result == "FOUND",
            "nsfw_score": nsfw_score
        }
        await r.set(f"automod:files:classification:{file_hash}", msgpack.packb(classification), ex=86400) 

        return classification

    def is_text_sexual(text: str) -> bool:
        """
        Returns whether the top classification of some text is sexual (S) or sexual/minors (S3).
        """
        
        top_classification = text_classifier(text)[0]["label"]
        return top_classification == "S" or top_classification == "S3"

    async def block_file(classification: FileClassification, flag_uploaders: bool = True):
        # Get file hash
        file_hash = classification["file_hash"]

        # Block file from being uploaded again
        db.blocked_files.insert_one({
            "_id": file_hash,
            "reason": f"Files automod - Malware: {classification['malware']}, NSFW Score: {classification['nsfw_score']}",
            "blocked_at": int(time.time())
        })

        # Delete file from S3
        for bucket in {file["bucket"] for file in files}:
            s3.remove_object(os.environ["S3_BUCKET"], f"{bucket}/{file_hash}")
            if bucket == "attachments":
                try:
                    s3.remove_object(os.environ["S3_BUCKET"], f"{bucket}/{file_hash}_thumbnail")
                except: pass

        # Get and delete all uploads of this file
        files = list(db.files.find({"hash": file_hash}, projection={"bucket": 1, "uploaded_by": 1}))
        db.files.delete_many({"hash": file_hash})

        # Get and delete all of the posts the file is included in
        uploaders = {file["uploaded_by"] for file in files if file["bucket"] == "attachments"}
        for uploader in uploaders:
            file_ids = [file["_id"] for file in files if file["bucket"] == "attachments" and file["uploaded_by"] == uploader]
            posts = list(db.posts.find({"u": uploader, "attachments": {"$in": file_ids}}, projection={"_id": 1, "u": 1}))
            for post in posts:
                await r.publish("admin", msgpack.packb({
                    "op": "delete_post",
                    "id": post["_id"]
                }))

                if flag_uploaders:
                    await flag_user(post["u"], classification, post_id=post["_id"])

    async def flag_user(username: str, classification: FileClassification, post_id: Optional[str] = None):
        # Add flag if one doesn't already exist for the classification
        if not db.automod_flags.find_one({"file_classification.file_hash": classification["file_hash"]}, projection={"_id": 1}):
            db.automod_flags.insert_one({
                "username": username,
                "time": int(time.time()),
                "file_classification": classification
            })
            await add_user_note(username, f"Files automod flag\nFile Hash: {classification['file_hash']}\nPost ID: {post_id}\nMalware: {classification['malware']}\nNSFW Score: {classification['nsfw_score']}")

        # Ban user if they have accumulated 3 or more flags in the last 24 hours
        if db.automod_flags.count_documents({"username": username, "time": {"$gt": int(time.time())-86400}}) >= 3:
            await ban_user(username)
            await add_user_note(username, "Was banned for accumulating 3 or more flags within 24 hours.")

        # Report post if specified
        if post_id:
            await r.publish("admin", msgpack.packb({
                "op": "report_post",
                "id": post["_id"],
                "reason": "Files automod flag",
                "comment": f"File Hash: {classification['file_hash']}, Malware: {classification['malware']}, NSFW Score: {classification['nsfw_score']}"
            }))

    async def alert_user(username: str, content: str):
        await r.publish("admin", msgpack.packb({
            "op": "alert_user",
            "username": username,
            "note": note
        }))

    async def add_user_note(username: str, note: str):
        await r.publish("admin", msgpack.packb({
            "op": "add_user_note",
            "username": username,
            "note": note
        }))

    async def ban_user(username: str):
        await r.publish("admin", msgpack.packb({
            "op": "ban_user",
            "user": username,
            "state": "perm_ban",
            "reason": ""
        }))

    # Start handling events
    async for message in pubsub.listen():
        try:
            # Parse event
            if message["type"] != "message":
                continue
            event: Event = msgpack.unpackb(message["data"])

            # Get file classifications
            file_classifications = {await get_file_classification(event["file_bucket"], file_hash) for file_hash in event["file_hashes"]}

            # Block bad files and flag uploaders
            for classification in file_classifications:
                if classification["malware"] or classification["nsfw_score"] >= NSFW_SCORE_THRESHOLD:
                    await block_file(classification, flag_uploaders=True)
        except Exception as e:
            print(f"{message}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
