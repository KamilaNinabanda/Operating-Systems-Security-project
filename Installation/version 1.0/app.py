import logging
import docker
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

try:
  docker_client = docker.from_env()
except Exception as e:
  logging.error(f"Failed to initialize Docker client: {e}")
  docker_client = None


def isolate_container(container_id, container_name):
  if not docker_client:
    logging.error("Docker client not available.")
    return False

  try:
    container = docker_client.containers.get(container_id)
    logging.warning(
        f"SECURITY ACTION: Isolating container {container_name} ({container_id})"
    )
    container.pause()
    logging.info(f"Successfully paused container: {container_name}")
    return True
  except Exception as e:
    logging.error(f"Failed to isolate container {container_id}: {e}")
  return False


@app.route("/webhook/falco", methods=["POST"])
def falco_webhook():
  data = request.json
  if not data:
    return jsonify({"status": "error", "message": "No data received"}), 400

  priority = data.get("priority", "NOTICE")
  container_id = data.get("output_fields", {}).get("container.id")
  container_name = data.get("output_fields", {}).get("container.name", "unknown")

  logging.info(
      f"Alert received: [{priority}] | Container: {container_name}"
  )

  if priority in ["WARNING", "ERROR", "CRITICAL"]:
    if container_id and container_id != "host":
      success = isolate_container(container_id, container_name)
      return (
          jsonify({
              "status": "success",
              "action_taken": "isolated" if success else "failed",
          }),
          200,
      )

  return jsonify({"status": "ignored"}), 200


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000)
