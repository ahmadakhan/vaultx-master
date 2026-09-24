import { LoginForm } from "@/components/login-form"

export default function HomePage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-[var(--container-form)] max-w-sm">
        <LoginForm />
      </div>
    </div>
  )
}
