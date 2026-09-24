"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

type TooltipContextValue = {
  open: boolean
  setOpen: (open: boolean) => void
  disabled: boolean
}

const TooltipContext = React.createContext<TooltipContextValue | null>(null)

function useTooltip() {
  const ctx = React.use(TooltipContext)
  if (!ctx) {
    throw new Error("Tooltip compound components must be used within <Tooltip>")
  }
  return ctx
}

function TooltipProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}

interface TooltipProps {
  children: React.ReactNode
  disabled?: boolean
  open?: boolean
  defaultOpen?: boolean
}

function Tooltip({
  children,
  disabled = false,
  open,
  defaultOpen = false,
}: TooltipProps) {
  const [openState, setOpenState] = React.useState(defaultOpen)
  const controlled = open !== undefined
  const isOpen = controlled ? open! : openState
  const setOpen = controlled ? () => {} : setOpenState

  return (
    <TooltipContext.Provider value={{ open: isOpen, setOpen, disabled }}>
      <div
        data-slot="tooltip"
        className="relative inline-flex"
        onMouseLeave={() => !disabled && setOpen(false)}
      >
        {children}
      </div>
    </TooltipContext.Provider>
  )
}

function TooltipTrigger({
  children,
  asChild = false,
}: {
  children: React.ReactNode
  asChild?: boolean
}) {
  const { setOpen, disabled } = useTooltip()

  const triggerProps = {
    onMouseEnter: () => !disabled && setOpen(true),
    onMouseLeave: () => !disabled && setOpen(false),
    onFocus: () => !disabled && setOpen(true),
    onBlur: () => !disabled && setOpen(false),
  }

  if (asChild) {
    return React.isValidElement(children)
      ? React.cloneElement(children as React.ReactElement, {
          ...triggerProps,
        })
      : <>{children}</>
  }

  return <div {...triggerProps}>{children}</div>
}

interface TooltipContentProps extends React.ComponentProps<"div"> {
  side?: "top" | "right" | "bottom" | "left"
}

function TooltipContent({
  className,
  children,
  side = "top",
  ...props
}: TooltipContentProps) {
  const { open, disabled } = useTooltip()

  const sideClasses = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
  }

  return (
    <div
      data-slot="tooltip-content"
      className={cn(
        "pointer-events-none absolute z-50",
        sideClasses[side],
        "invisible transition-opacity duration-150",
        open && !disabled
          ? "visible opacity-100"
          : "opacity-0",
        className
      )}
      {...props}
    >
      <div className="rounded-md bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-md border border-border whitespace-nowrap">
        {children}
      </div>
    </div>
  )
}

export { Tooltip, TooltipProvider, TooltipTrigger, TooltipContent }
