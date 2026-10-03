'use client'

import { Sparkles, TrendingUp, Code2, BookOpen } from 'lucide-react'
import { useI18n } from '@/lib/i18n/i18n-context'

interface EmptyStateProps {
  onStarterClick?: (text: string) => void
}

export function EmptyState({ onStarterClick }: EmptyStateProps) {
  const { t } = useI18n()
  const starters = [
    { icon: TrendingUp, text: t('starterAnalyze') },
    { icon: Code2, text: t('starterWrite') },
    { icon: BookOpen, text: t('starterSummarize') },
    { icon: Sparkles, text: t('starterPlan') },
  ]

  return (
    <div className="mx-auto flex min-h-full w-full max-w-3xl flex-col items-center justify-center px-4 py-8">
      <div className="mb-8 space-y-3 text-center">
        <img src="/logo.png" alt="Weaver" className="mx-auto h-12 w-12 object-contain" />
        <h2 className="text-3xl font-semibold tracking-tight">{t('emptyStateTitle')}</h2>
        <p className="text-sm text-muted-foreground">{t('askAnything')}</p>
      </div>
      <div className="grid w-full max-w-2xl grid-cols-1 gap-3 sm:grid-cols-2">
        {starters.map(starter => (
          <button
            key={starter.text}
            type="button"
            onClick={() => onStarterClick?.(starter.text)}
            className="flex items-start gap-3 rounded-xl border border-border/60 p-4 text-left text-sm text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground"
          >
            <starter.icon className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{starter.text}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
