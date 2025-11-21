#!/bin/bash
# Test script to verify /api/forward endpoint is working

echo "================================"
echo "Testing /api/forward endpoint"
echo "================================"
echo ""

# Get the generated token from the JSON file
TOKEN=$(cat data/auth/4904ffff-a98d-597d-aca9-7bd0ba1658be.json | grep -o '"target_id": "[^"]*"' | cut -d'"' -f4)
echo "Using token: $TOKEN"
echo ""

# Test 1: Test endpoint
echo "Test 1: Checking if server is running..."
curl -X GET http://localhost:5000/api/forward/test
echo -e "\n"

# Test 2: POST with valid token
echo "Test 2: POSTing to /api/forward/<token>..."
curl -X POST http://localhost:5000/api/forward/$TOKEN \
  -H "Content-Type: application/json" \
  -d '{
    "caller": "+4922197580971",
    "agent_name": "AI Assistant",
    "customer_name": "Max Mustermann",
    "customer_number": "+4922197580971",
    "customer_email": "max@example.com",
    "concerns": ["Frage zu Bestellung #1234", "Liefertermin klären"],
    "tasks": ["Bestellstatus prüfen", "Liefertermin bestätigen"],
    "summary": "Test summary from curl"
  }'
echo -e "\n"

echo "================================"
echo "Check Flask console for logs!"
echo "================================"
