<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuthStore } from '../../stores/auth'
import api from '../../api/client'

const auth = useAuthStore()

const stats = ref({ posts: 0, releases: 0, demos: 0, projects: 0 })

onMounted(async () => {
  const [blogRes, relRes, demoRes, projRes] = await Promise.all([
    api.get('/admin/blog', { params: { limit: 1 } }).catch(() => ({ data: { total: 0 } })),
    api.get('/music/releases').catch(() => ({ data: [] })),
    api.get('/music/demos').catch(() => ({ data: [] })),
    api.get('/projects').catch(() => ({ data: [] })),
  ])
  stats.value = {
    posts: blogRes.data.total || 0,
    releases: Array.isArray(relRes.data) ? relRes.data.length : 0,
    demos: Array.isArray(demoRes.data) ? demoRes.data.length : 0,
    projects: Array.isArray(projRes.data) ? projRes.data.length : 0,
  }
})

const cards = [
  { key: 'posts', label: 'Blog Posts', color: 'text-blue-400 bg-blue-400/10', to: '/admin/blog',
    icon: 'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z' },
  { key: 'releases', label: 'Releases', color: 'text-emerald-400 bg-emerald-400/10', to: '/admin/releases',
    icon: 'M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2z' },
  { key: 'demos', label: 'Demos', color: 'text-amber-400 bg-amber-400/10', to: '/admin/demos',
    icon: 'M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z' },
  { key: 'projects', label: 'Projects', color: 'text-purple-400 bg-purple-400/10', to: '/admin/projects',
    icon: 'M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6z' },
]
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-2xl font-bold">Dashboard</h1>
      <p class="text-gray-500 text-sm mt-1">Welcome back, {{ auth.user?.username }}</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      <router-link v-for="card in cards" :key="card.key" :to="card.to"
        class="group bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 hover:border-gray-700/50 transition">
        <div class="flex items-center justify-between mb-4">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center" :class="card.color">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" :d="card.icon" />
            </svg>
          </div>
          <svg class="w-4 h-4 text-gray-700 group-hover:text-gray-400 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
        </div>
        <div class="text-3xl font-bold">{{ (stats as any)[card.key] }}</div>
        <div class="text-xs text-gray-500 mt-1">{{ card.label }}</div>
      </router-link>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <router-link to="/admin/radio"
        class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 hover:border-gray-700/50 transition flex items-center gap-4">
        <div class="w-10 h-10 rounded-xl flex items-center justify-center text-red-400 bg-red-400/10">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
          </svg>
        </div>
        <div>
          <div class="font-semibold">Radio Stream</div>
          <div class="text-xs text-gray-500">Manage live radio</div>
        </div>
      </router-link>

      <router-link to="/admin/nav-links"
        class="bg-[#12121f] border border-gray-800/40 rounded-2xl p-5 hover:border-gray-700/50 transition flex items-center gap-4">
        <div class="w-10 h-10 rounded-xl flex items-center justify-center text-cyan-400 bg-cyan-400/10">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
        </div>
        <div>
          <div class="font-semibold">Navigation Links</div>
          <div class="text-xs text-gray-500">Manage external links</div>
        </div>
      </router-link>
    </div>
  </div>
</template>
