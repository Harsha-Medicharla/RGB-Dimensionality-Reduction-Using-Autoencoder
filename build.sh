#!/usr/bin/env bash
# Exit on error
set -o errexit

echo "=========================================="
echo "Starting Build Process"
echo "=========================================="

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo "✓ Dependencies installed"

# Check for model files
echo ""
echo "Checking for required model files..."
if [ -f "enhanced_autoencoder.keras" ]; then
    echo "✓ enhanced_autoencoder.keras found ($(du -h enhanced_autoencoder.keras | cut -f1))"
else
    echo "✗ ERROR: enhanced_autoencoder.keras NOT FOUND!"
    echo "Please upload the model file to your repository"
    exit 1
fi

if [ -f "rgb_projector.keras" ]; then
    echo "✓ rgb_projector.keras found ($(du -h rgb_projector.keras | cut -f1))"
else
    echo "✗ ERROR: rgb_projector.keras NOT FOUND!"
    echo "Please upload the model file to your repository"
    exit 1
fi

# Create media directories
echo ""
echo "Creating media directories..."
mkdir -p media/uploads/input
mkdir -p media/uploads/output
echo "✓ Media directories created"

# Collect static files
echo ""
echo "Collecting static files..."
python manage.py collectstatic --no-input
echo "✓ Static files collected"

# Run migrations
echo ""
echo "Running database migrations..."
python manage.py migrate --no-input
echo "✓ Migrations completed"

# Check database connection
echo ""
echo "Checking database connection..."
python manage.py check --database default
echo "✓ Database connection verified"

echo ""
echo "=========================================="
echo "Build Process Completed Successfully"
echo "=========================================="