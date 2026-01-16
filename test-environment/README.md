# Test Environment for React2Shell

## Setup

### Using Docker

```bash
# Build the image
docker build -t vuln-nextjs .

# Run the container (isolated network recommended)
docker run --rm -p 3000:3000 --network none vuln-nextjs
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
./react2shell -u http://localhost:3000 --safe-check

# If vulnerable, try exploit
./react2shell -u http://localhost:3000 --exploit -c "id"
```

## Cleanup

```bash
# Stop and remove container
docker stop $(docker ps -q --filter ancestor=vuln-nextjs)

# Remove image
docker rmi vuln-nextjs
```
