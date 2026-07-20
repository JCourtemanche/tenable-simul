#!/bin/bash
# Cloud Run deployment script for the Tenable.io API simulator.
# Usage: bash deploy-cloudrun.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="europe-west1"
SERVICE_NAME="tenable-simulator"
REPO_NAME="tenable-simulator"

TENABLE_ACCESS_KEY="${TENABLE_ACCESS_KEY:-tenable-access-key}"
TENABLE_SECRET_KEY="${TENABLE_SECRET_KEY:-tenable-secret-key}"

echo -e "${GREEN}=== Cloud Run deployment - Tenable.io Simulator ===${NC}\n"
echo -e "${YELLOW}Project:${NC} $PROJECT_ID"
echo -e "${YELLOW}Region:${NC}  $REGION"
echo -e "${YELLOW}Service:${NC} $SERVICE_NAME"
echo ""

echo -e "${YELLOW}[1/6] Enabling APIs...${NC}"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
echo -e "${GREEN}OK - APIs enabled${NC}\n"

echo -e "${YELLOW}[2/6] Configuring Artifact Registry...${NC}"
REPO_EXISTS=$(gcloud artifacts repositories list --location=$REGION --filter="name:$REPO_NAME" --format="value(name)" 2>/dev/null)
if [ -z "$REPO_EXISTS" ]; then
  gcloud artifacts repositories create $REPO_NAME --repository-format=docker --location=$REGION --description="Tenable.io simulator images" --quiet
  echo -e "${GREEN}OK - Repository created${NC}"
else
  echo -e "${GREEN}OK - Repository already exists${NC}"
fi
echo ""

echo -e "${YELLOW}[3/6] Checking Dockerfile...${NC}"
[ -f "deployment/Dockerfile" ] || { echo -e "${RED}ERROR: Dockerfile not found${NC}"; exit 1; }
echo -e "${GREEN}OK${NC}\n"

echo -e "${YELLOW}[4/6] Building Docker image...${NC}"
gcloud builds submit --config cloudbuild.yaml
IMAGE_PATH="${REGION}-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/tenable-simulator:latest"
echo -e "${GREEN}OK - Image built: $IMAGE_PATH${NC}\n"

echo -e "${YELLOW}[5/6] Deploying to Cloud Run...${NC}"
gcloud run deploy $SERVICE_NAME \
  --image $IMAGE_PATH --platform managed --region $REGION \
  --allow-unauthenticated --memory 512Mi --cpu 1 --timeout 300 \
  --min-instances 0 --max-instances 2 \
  --set-env-vars "TENABLE_ACCESS_KEY=${TENABLE_ACCESS_KEY},TENABLE_SECRET_KEY=${TENABLE_SECRET_KEY},DEBUG=False"

echo -e "${YELLOW}[6/6] Configuring public access...${NC}"
gcloud run services add-iam-policy-binding $SERVICE_NAME --region=$REGION --member=allUsers --role=roles/run.invoker --project=$PROJECT_ID --quiet 2>/dev/null || true

SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)')

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Deployment successful!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Service URL:${NC} ${GREEN}$SERVICE_URL${NC}"
echo ""
echo "1. Health:  curl $SERVICE_URL/health"
echo "2. Scans:   curl -H 'X-ApiKeys: accessKey=${TENABLE_ACCESS_KEY}; secretKey=${TENABLE_SECRET_KEY}' $SERVICE_URL/scans"
echo "3. Export:  curl -X POST -H 'X-ApiKeys: accessKey=${TENABLE_ACCESS_KEY}; secretKey=${TENABLE_SECRET_KEY}' -H 'Content-Type: application/json' -d '{\"chunk_size\":500,\"filters\":{}}' $SERVICE_URL/assets/export"
echo ""
echo -e "${YELLOW}XSIAM configuration (Tenable.io):${NC}"
echo "   Server URL: $SERVICE_URL"
echo "   Access Key: ${TENABLE_ACCESS_KEY}"
echo "   Secret Key: ${TENABLE_SECRET_KEY}"
echo ""
