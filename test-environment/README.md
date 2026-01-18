# Test Environment for React2Shell

## Setup

### Using Docker Compose

```bash
# Run the test environment
docker-compose up

# To run in background
docker-compose up -d
```

### Manual Setup

If you prefer manual setup:

```bash
mkdir vuln-nextjs && cd vuln-nextjs
npm init -y
npm install next@15.1.0 react@19 react-dom@19

# Create app structure and copy files from this directory
npx next dev
```

## Testing

Once the application is running:

```bash
# From project root
./react2shell_macos_apple_silicon -u http://localhost:3000 --safe-check

# If vulnerable, try exploit
./react2shell_macos_apple_silicon -u http://localhost:3000 --exploit -c "id"
```

## Cleanup

```bash
# Stop and remove the container
docker-compose down
```
