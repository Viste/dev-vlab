<script setup lang="ts">
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()

const links = [
  { to: '/admin', label: 'Dashboard', icon: '~' },
  { to: '/admin/blog', label: 'Blog', icon: '#' },
  { to: '/admin/releases', label: 'Releases', icon: '>' },
  { to: '/admin/demos', label: 'Demos', icon: '>' },
  { to: '/admin/radio', label: 'Radio', icon: '>' },
  { to: '/admin/projects', label: 'Projects', icon: '>' },
  { to: '/admin/nav-links', label: 'Nav Links', icon: '>' },
]
</script>

<template>
  <div class="min-h-screen flex bg-gray-950 text-gray-100">
    <aside class="w-52 border-r border-gray-800/50 p-4 space-y-1 shrink-0 bg-gray-950/50">
      <router-link to="/" class="flex items-center gap-2 mb-6 hover:opacity-80 transition">
        <span class="text-lg font-bold text-purple-400">V</span>
        <span class="text-xs font-semibold text-gray-400">Admin</span>
      </router-link>
      <router-link v-for="link in links" :key="link.to" :to="link.to"
        class="block px-3 py-2 rounded-xl text-sm text-gray-400 hover:text-white hover:bg-gray-800/50 transition"
        active-class="!bg-gray-800/80 !text-purple-400">
        {{ link.label }}
      </router-link>
      <hr class="border-gray-800/50 my-4" />
      <router-link to="/" class="block px-3 py-2 rounded-xl text-sm text-gray-500 hover:text-white transition">Back to site</router-link>
      <button @click="auth.logout()" class="block px-3 py-2 text-sm text-gray-500 hover:text-white transition w-full text-left">Logout</button>
    </aside>

    <div class="flex-1 p-6 overflow-auto">
      <router-view />
    </div>
  </div>
</template>
