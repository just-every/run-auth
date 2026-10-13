import { createFileRoute } from '@tanstack/react-router'

// The server owns authorization and renders Auth documents before Start routes.
export const Route = createFileRoute('/')({ component: () => null })
