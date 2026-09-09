import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 rounded-md text-xs font-semibold whitespace-nowrap transition-all outline-none focus-visible:ring-2 focus-visible:ring-white disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 cursor-pointer active:scale-95",
  {
    variants: {
      variant: {
        default: "bg-white text-zinc-950 hover:bg-zinc-200 shadow-md font-semibold border border-white",
        destructive:
          "bg-red-950 text-red-200 border border-red-800 hover:bg-red-900 focus-visible:ring-red-500",
        outline:
          "border border-zinc-700 bg-zinc-900/90 text-zinc-100 shadow-xs hover:bg-zinc-800 hover:border-zinc-500 hover:text-white",
        secondary:
          "bg-zinc-800 text-zinc-100 hover:bg-zinc-700 border border-zinc-700",
        ghost:
          "text-zinc-400 hover:bg-zinc-800/80 hover:text-zinc-100",
        link: "text-zinc-200 underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        xs: "h-6 gap-1 rounded-md px-2 text-xs has-[>svg]:px-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-8 gap-1.5 rounded-md px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-md px-6 has-[>svg]:px-4",
        icon: "size-9",
        "icon-xs": "size-6 rounded-md [&_svg:not([class*='size-'])]:size-3",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : "button"

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
