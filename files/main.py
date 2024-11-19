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

class EventType(Enum):
    NEW_UPLOAD = 0
    NEW_POST = 1
    POST_REPORTED = 2

class Event(TypedDict):
    type: EventType
    username: str
    file_bucket: Literal["icons", "emojis", "stickers", "attachments"]
    file_hashes: list[str]
    post_id: Optional[str]
    post_content: Optional[str]

class FileClassification(TypedDict):
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
    cd = clamd.ClamdUnixSocket(path=os.environ["CLAMD_SOCK"])

    # Initialise Hugging Face classifiers
    nsfw_image_detection = pipeline("image-classification", model="Falconsai/nsfw_image_detection")
    text_classifier = pipeline("text-classification", model="KoalaAI/Text-Moderation")

    async def get_file_classification(bucket: str, hash: str) -> FileClassification:
        # Cached classification
        classification = await r.get(f"automod:files:classification:{hash}")
        if classification:
            classification: FileClassification = msgpack.unpackb(classification)
            return classification
        
        # Create file path
        fp = os.environ["TEMP_DIR"] + "/" + hash

        # Get file mime
        mime: str = db.files.find_one({"hash": hash})["mime"]

        # Download file to RAM dir
        if mime.startswith("video/"):  # download thumbnail for videos
            s3.fget_object(bucket, hash+"_thumbnail", fp)
        else:
            s3.fget_object(bucket, hash, fp)

        # Scan with ClamAV
        clam_result, _ = list(cd.scan(fp).values())[0]

        # Scan for NSFW if file is an image
        nsfw_score = 0
        if mime.startswith("image/"):
            for item in nsfw_image_detection(Image.open(fp)):
                if item["label"] == "nsfw":
                    nsfw_score = item["score"]

        # Remove file
        os.remove(fp)

        # Create and cache classification for 24 hours
        classification: FileClassification = {
            "malware": clam_result == "FOUND",
            "nsfw_score": nsfw_score
        }
        await r.set(f"automod:files:classification:{hash}", msgpack.packb(classification), ex=86400) 

        return classification

    def is_user_new(username: str) -> bool:
        return bool(db.usersv0.count_documents({"_id": username, "created": {"$gt": 1731974400}}, limit=1))

    def is_text_sexual(text: str) -> bool:
        """
        Returns whether the top classification of some text is sexual (S) or sexual/minors (S3).
        """
        
        top_classification = text_classifier(text)[0]["label"]
        return top_classification == "S" or top_classification == "S3"

    async def block_files(hashes: list[str], reason: str, send_alerts: bool = True, post_id: str = None):
        for file_hash in hashes:
            try:
                # Block file from being uploaded again
                db.blocked_files.insert_one({
                    "_id": file_hash,
                    "reason": reason,
                    "blocked_at": int(time.time())
                })

                # Get all uploads of this file
                files = list(db.files.find({"hash": file_hash}, projection={"bucket": 1, "uploaded_by": 1}))

                # Send alert to uploaders
                if send_alerts:
                    uploaders = {file["uploaded_by"] for file in files}
                    for username in uploaders:
                        await r.publish("admin", msgpack.packb({
                            "op": "alert_user",
                            "user": username,
                            "content": "We've detected that one or more of your uploaded files on Meower contains prohibited content. To help keep our community safe, please avoid sharing files with malware, explicit content, or other restricted material."
                        }))

                # Delete post
                if post_id:
                    await r.publish("admin", msgpack.packb({
                        "op": "delete_post",
                        "id": post_id
                    }))

                # Delete file from S3
                for bucket in {file["bucket"] for file in files}:
                    s3.remove_object(bucket, file_hash)
                    if bucket == "attachments":
                        try:
                            s3.remove_object(bucket, file_hash+"_thumbnail")
                        except: pass
                

            except Exception as e:
                print(e)

    async def flag_user(username: str, classifications: dict[str, FileClassification], auto_ban: bool = True):
        # Log classifications
        for file_hash, classification in classifications.items():
            db.file_classifications.update_one({"_id": {"username": username, "hash": file_hash}}, {"$set": {
                "classification": classification,
                "time": int(time.time())
            }}, upsert=True)

        # Ban user if they have 3 or more classifications in the last 24 hours
        if auto_ban and db.file_classifications.count_documents({"_id.username": username, "time": {"$gt": int(time.time())-86400}}) >= 3:
            await ban_user(username)

    async def ban_user(username: str):
        # Ban user
        await r.publish("admin", msgpack.packb({
            "op": "ban_user",
            "user": username,
            "state": "perm_ban",
            "reason": "We've detected that one or more of your uploaded files on Meower contains prohibited content. To help keep our community safe, please avoid sharing files with malware, explicit content, or other restricted material.",
            "note": f"File classifications that lead to ban:\n{json.dumps([{classification['_id']['hash']: classification['classification']} for classification in db.file_classifications.find({'_id.username': username})])}"
        }))

        # Block previously classified likely NSFW files
        file_hashes = [
            classification["_id"]["hash"]
            for classification in db.file_classifications.find({
                "_id.username": username,
                "classification.nsfw_score": {"$gte": 0.75}
            })
        ]
        await block_files(file_hashes, "likely_nsfw_and_user_banned")

    # Start handling events
    async for message in pubsub.listen():
        try:
            # Parse event
            if message["type"] != "message":
                continue
            event: Event = msgpack.unpackb(message["data"])

            # Get file classifications
            file_classifications: dict[str, FileClassification] = {
                hash: await get_file_classification(event["file_bucket"], hash)
                for hash in event["file_hashes"]
            }

            # Get file hashes of malware
            malware = [
                hash
                for hash, classification in file_classifications.items()
                if classification["malware"]
            ]

            # Get file hashes of likely NSFW
            likely_nsfw = [
                hash
                for hash, classification in file_classifications.items()
                if classification["nsfw_score"] >= 0.75
            ]

            # Escape if no malware or likely NSFW is detected
            if len(malware) == 0 and len(likely_nsfw) == 0:
                continue

            # Block malware
            await block_files(malware, "malware", post_id=event.get("post_id"))

            # Block likely NSFW if the uploader's account is made after November 19th, the post likely contains inappropriate text, or the post is reported
            if event["type"] == EventType.NEW_UPLOAD.value and is_user_new(event["username"]):
                await block_files(likely_nsfw, "likely_nsfw_and_new_account", post_id=event.get("post_id"))
            elif event["type"] == EventType.NEW_POST.value and is_text_sexual(event["post_content"]):
                await block_files(likely_nsfw, "likely_nsfw_and_inappropriate_post_content", post_id=event.get("post_id"))
            elif event["type"] == EventType.POST_REPORTED.value:
                await block_files(likely_nsfw, "likely_nsfw_and_post_reported", post_id=event.get("post_id"))

            # Flag user for malware and likely NSFW files
            await flag_user(event["username"], {
                hash: classification
                for hash, classification in file_classifications.items()
                if classification["malware"] or classification["nsfw_score"] >= 0.75
            }, auto_ban=True)
        except Exception as e:
            print(f"{message}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
