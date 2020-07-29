#!/bin/bash
set -e

podman build -t crypto-chat .
podman push crypto-chat docker://registry.psycho-appz.net/crypto-chat:latest
kubectl rollout restart deployment/crypto-chat-app
