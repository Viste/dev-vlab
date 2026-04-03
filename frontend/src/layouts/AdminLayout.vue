<script setup lang="ts">
import { useAuthStore } from '../stores/auth'

const auth = useAuthStore()

const links = [
  { to: '/admin', label: 'Dashboard' },
  { to: '/admin/blog', label: 'Blog' },
  { to: '/admin/releases', label: 'Releases' },
  { to: '/admin/demos', label: 'Demos' },
  { to: '/admin/radio', label: 'Radio' },
  { to: '/admin/projects', label: 'Projects' },
  { to: '/admin/nav-links', label: 'Nav Links' },
]
</script>

<template>
  <div class="min-h-screen flex bg-gray-950 text-gray-100">
    <aside class="w-56 border-r border-gray-800 p-4 space-y-2 shrink-0">
      <router-link to="/" class="text-lg font-bold block mb-4 hover:text-purple-400">dev-vlab</router-link>
      <router-link
        v-for="link in links"
        :key="link.to"
        :to="link.to"
        class="block px-3 py-2 rounded hover:bg-gray-800 transition text-sm"
        active-class="bg-gray-800 text-purple-400"
      >
        {{ link.label }}
      </router-link>
      <hr class="border-gray-800 my-4" />
      <button @click="auth.logout()" class="text-sm text-gray-400 hover:text-white px-3">Logout</button>
    </aside>

    <div class="flex-1 p-6 overflow-auto">
      <router-view />
    </div>
  </div>
</template>
