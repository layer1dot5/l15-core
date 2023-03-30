#!/bin/bash

# Define variables
FILE_NAME="Dockerfile.build_python_plugin"
IMAGE_NAME="build_python_plugin"
CONTAINER_NAME="l15-build-python-plugin"
BUILD_DIR="/l15/l15-core/build/src/python_binding"
HOST_DIR="./build/python_binding_from_docker"

# Build the Docker image
docker build -t $IMAGE_NAME -f $FILE_NAME .

# Create and run a temporary container
docker create --name $CONTAINER_NAME $IMAGE_NAME

mkdir -p $HOST_DIR
# Copy the built files from the container to the host
docker cp $CONTAINER_NAME:$BUILD_DIR/__init__.py $HOST_DIR/__init__.py
docker cp $CONTAINER_NAME:$BUILD_DIR/libl15_core_pybind.py $HOST_DIR/libl15_core_pybind.py
docker cp $CONTAINER_NAME:$BUILD_DIR/_libl15_core_pybind.so $HOST_DIR/_libl15_core_pybind.so

# Remove the temporary container
docker rm $CONTAINER_NAME
