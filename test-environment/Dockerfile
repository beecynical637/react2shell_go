FROM node:20-alpine
WORKDIR /app
RUN npm init -y && \
    npm install next@15.1.0 react@19 react-dom@19
RUN mkdir -p app/actions
COPY <<EOF app/actions/index.js
'use server'

export async function testAction(formData) {
  // Vulnerable Server Action
  return { success: true }
}
EOF

COPY <<EOF app/page.js
import { testAction } from './actions'

export default function Home() {
  return (
    <main>
      <h1>Test Application</h1>
      <form action={testAction}>
        <button type="submit">Submit</button>
      </form>
    </main>
  )
}
EOF

COPY <<EOF app/layout.js
export const metadata = {
  title: 'Test App',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
EOF

COPY <<EOF next.config.js
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['*']
    }
  }
}
EOF

EXPOSE 3000

CMD ["npx", "next", "dev"]
