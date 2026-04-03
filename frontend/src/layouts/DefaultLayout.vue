<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'
import type { NavigationLink } from '../api/types'

const auth = useAuthStore()
const navLinks = ref<NavigationLink[]>([])
const menuOpen = ref(false)

onMounted(async () => {
  try {
    const { data } = await api.get<NavigationLink[]>('/nav-links')
    navLinks.value = data
  } catch { /* ok */ }
})
</script>

<template>
  <div class="min-h-screen flex flex-col bg-gray-950 text-gray-100">
    <header class="border-b border-gray-800 bg-gray-950/80 backdrop-blur sticky top-0 z-50">
      <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
        <router-link to="/" class="text-xl font-bold tracking-tight hover:text-purple-400 transition">
          dev-vlab
        </router-link>

        <nav class="hidden md:flex items-center gap-6">
          <router-link to="/" class="nav-link">Home</router-link>
          <router-link to="/blog" class="nav-link">Blog</router-link>
          <router-link to="/music" class="nav-link">Music</router-link>
          <a
            v-for="link in navLinks"
            :key="link.id"
            :href="link.url"
            target="_blank"
            class="nav-link"
          >{{ link.title }}</a>
          <template v-if="auth.isLoggedIn">
            <router-link to="/profile" class="nav-link">Profile</router-link>
            <router-link v-if="auth.isAdmin" to="/admin" class="nav-link text-purple-400">Admin</router-link>
            <button @click="auth.logout()" class="nav-link">Logout</button>
          </template>
          <router-link v-else to="/login" class="nav-link">Login</router-link>
        </nav>

        <button class="md:hidden p-2" @click="menuOpen = !menuOpen">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              :d="menuOpen ? 'M6 18L18 6M6 6l12 12' : 'M4 6h16M4 12h16M4 18h16'" />
          </svg>
        </button>
      </div>

      <div v-if="menuOpen" class="md:hidden border-t border-gray-800 px-4 py-3 space-y-2">
        <router-link to="/" class="block nav-link" @click="menuOpen = false">Home</router-link>
        <router-link to="/blog" class="block nav-link" @click="menuOpen = false">Blog</router-link>
        <router-link to="/music" class="block nav-link" @click="menuOpen = false">Music</router-link>
        <template v-if="auth.isLoggedIn">
          <router-link to="/profile" class="block nav-link" @click="menuOpen = false">Profile</router-link>
          <router-link v-if="auth.isAdmin" to="/admin" class="block nav-link text-purple-400" @click="menuOpen = false">Admin</router-link>
          <button @click="auth.logout(); menuOpen = false" class="block nav-link">Logout</button>
        </template>
        <router-link v-else to="/login" class="block nav-link" @click="menuOpen = false">Login</router-link>
      </div>
    </header>

    <main class="flex-1">
      <router-view />
    </main>

    <footer class="border-t border-gray-800 py-6 text-center text-gray-500 text-sm">
      &copy; {{ new Date().getFullYear() }} dev-vlab
    </footer>
  </div>
</template>
