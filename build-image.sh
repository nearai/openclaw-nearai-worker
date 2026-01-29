#!/bin/bash

# Parse command line arguments
PUSH=false
REPO=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            PUSH=true
            REPO="$2"
            if [ -z "$REPO" ]; then
                echo "Error: --push requires a repository argument"
                echo "Usage: $0 [--push <repo>[:<tag>]]"
                exit 1
            fi
            shift 2
            ;;
        *)
            echo "Usage: $0 [--push <repo>[:<tag>]]"
            exit 1
            ;;
    esac
done

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found in PATH" >&2
        exit 1
    fi
}

for required in docker skopeo jq git; do
    require_command "$required"
done

# Check if buildkit_20 already exists before creating it
if ! docker buildx inspect buildkit_20 &>/dev/null; then
    docker buildx create --use --driver-opt image=moby/buildkit:v0.20.2 --name buildkit_20
fi

# Create .GIT_REV file for build tracking
git rev-parse HEAD > .GIT_REV

TEMP_TAG="moltbot-nearai-worker-temp:$(date +%s)"
docker buildx build --builder buildkit_20 --no-cache --platform linux/amd64 \
    --build-arg SOURCE_DATE_EPOCH="0" \
    --output type=oci,dest=./oci.tar,rewrite-timestamp=true \
    --output type=docker,name="$TEMP_TAG",rewrite-timestamp=true .

if [ "$?" -ne 0 ]; then
    echo "Build failed"
    rm -f .GIT_REV
    exit 1
fi

echo "Build completed, manifest digest:"
echo ""
skopeo inspect oci-archive:./oci.tar | jq .Digest
echo ""

if [ "$PUSH" = true ]; then
    echo "Pushing image to $REPO..."
    skopeo copy --insecure-policy oci-archive:./oci.tar docker://"$REPO"
    echo "Image pushed successfully to $REPO"
else
    echo "To push the image to a registry, run:"
    echo ""
    echo " $0 --push <repo>[:<tag>]"
    echo ""
    echo "Or use skopeo directly:"
    echo ""
    echo " skopeo copy --insecure-policy oci-archive:./oci.tar docker://<repo>[:<tag>]"
    echo ""
fi
echo ""

# Extract package information from the built image (optional, for tracking)
echo "Extracting package information from built image: $TEMP_TAG"
if docker run --rm --entrypoint bash "$TEMP_TAG" -c "dpkg -l 2>/dev/null | grep '^ii' | awk '{print \$2\"=\"\$3}' | sort" > pinned-packages.txt 2>/dev/null; then
    if [ -s pinned-packages.txt ]; then
        echo "Package information extracted to pinned-packages.txt ($(wc -l < pinned-packages.txt) packages)"
    else
        echo "No Debian packages found (image may use Alpine or other base)"
        rm -f pinned-packages.txt
    fi
else
    echo "Could not extract package information"
    rm -f pinned-packages.txt
fi

# Clean up the temporary image from Docker daemon
docker rmi "$TEMP_TAG" 2>/dev/null || true

rm -f .GIT_REV

