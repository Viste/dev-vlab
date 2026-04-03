<script setup lang="ts">
import { useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const auth = useAuthStore()

const sections = [
  {
    title: 'Content',
    links: [
      { to: '/admin', label: 'Dashboard', exact: true, icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
      { to: '/admin/blog', label: 'Blog', icon: 'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z' },
      { to: '/admin/projects', label: 'Projects', icon: 'M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z' },
      { to: '/admin/nav-links', label: 'Links', icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1' },
    ],
  },
  {
    title: 'Music',
    links: [
      { to: '/admin/releases', label: 'Releases', icon: 'M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3' },
      { to: '/admin/demos', label: 'Demos', icon: 'M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z' },
      { to: '/admin/radio', label: 'Radio', icon: 'M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z' },
    ],
  },
]

function isActive(link: { to: string; exact?: boolean }) {
  if (link.exact) return route.path === link.to
  return route.path.startsWith(link.to)
}
</script>

<template>
  <div class="min-h-screen flex bg-[#0a0a14] text-gray-100">
    <aside class="w-56 shrink-0 flex flex-col border-r border-gray-800/30 bg-[#0d0d1a]">
      <router-link to="/" class="flex items-center gap-2.5 px-5 py-5 hover:opacity-80 transition">
        <img src="/favicon.svg" class="w-6 h-6" alt="V" />
        <span class="text-sm font-bold tracking-wide">Viste Lab</span>
      </router-link>

      <nav class="flex-1 px-3 space-y-5 mt-2">
        <div v-for="section in sections" :key="section.title">
          <p class="text-[10px] uppercase tracking-widest text-gray-600 px-3 mb-2">{{ section.title }}</p>
          <div class="space-y-0.5">
            <router-link v-for="link in section.links" :key="link.to" :to="link.to"
              class="flex items-center gap-3 px-3 py-2 rounded-xl text-sm transition"
              :class="isActive(link)
                ? 'bg-red-500/10 text-red-400'
                : 'text-gray-400 hover:text-white hover:bg-white/5'">
              <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" :d="link.icon" />
              </svg>
              {{ link.label }}
            </router-link>
          </div>
        </div>
      </nav>

      <div class="px-3 py-4 border-t border-gray-800/30 space-y-0.5">
        <router-link to="/"
          class="flex items-center gap-3 px-3 py-2 rounded-xl text-sm text-gray-500 hover:text-white hover:bg-white/5 transition">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to site
        </router-link>
        <button @click="auth.logout()"
          class="flex items-center gap-3 px-3 py-2 rounded-xl text-sm text-gray-500 hover:text-white hover:bg-white/5 transition w-full text-left">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
          </svg>
          Logout
        </button>
      </div>
    </aside>

    <div class="flex-1 overflow-auto">
      <header class="sticky top-0 z-10 bg-[#0a0a14]/80 backdrop-blur-xl border-b border-gray-800/30 px-6 py-4">
        <div class="flex items-center justify-between">
          <div></div>
          <div class="flex items-center gap-3">
            <span class="text-xs text-gray-500">{{ auth.user?.username }}</span>
            <div class="w-8 h-8 rounded-full bg-gray-800 flex items-center justify-center text-xs font-bold text-red-400">
              {{ auth.user?.username?.[0]?.toUpperCase() }}
            </div>
          </div>
        </div>
      </header>
      <div class="p-6">
        <router-view />
      </div>
    </div>
  </div>
</template>
