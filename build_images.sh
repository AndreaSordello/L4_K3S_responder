#!/bin/bash

# ───── SETTINGS ─────
IMAGE1_NAME="andreasordello/toolbox"
IMAGE2_NAME="andreasordello/l4-responder"
TAG="latest"

# ───── BUILD IMAGES ─────
echo "📦 Building Docker images..."
docker build -t $IMAGE1_NAME:$TAG ./Dockerfile-toolbox
docker build -t $IMAGE2_NAME:$TAG ./Dockerfile-responder

# ───── PUSH IMAGES ─────
echo "🚀 Pushing images to remote repository..."
docker push $IMAGE1_NAME:$TAG
docker push $IMAGE2_NAME:$TAG

echo "✅ Done!"