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
  <div class="min-h-screen flex flex-col bg-[#0a0a14] text-gray-100">
    <header class="sticky top-0 z-50 bg-[#0a0a14]/80 backdrop-blur-xl border-b border-white/[0.04]">
      <div class="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
        <router-link to="/" class="flex items-center gap-2.5 hover:opacity-80 transition">
          <img src="/favicon.svg" class="w-5 h-5" alt="V" />
          <span class="text-sm font-bold tracking-wide hidden sm:inline">Viste Lab</span>
        </router-link>

        <nav class="hidden md:flex items-center bg-white/[0.04] rounded-xl p-1 gap-0.5">
          <router-link to="/" class="tab-link" :class="{ 'tab-active': $route.path === '/' }">Home</router-link>
          <router-link to="/blog" class="tab-link" :class="{ 'tab-active': $route.path.startsWith('/blog') }">Blog</router-link>
          <router-link to="/music" class="tab-link" :class="{ 'tab-active': $route.path === '/music' }">Music</router-link>
        </nav>

        <div class="hidden md:flex items-center gap-3">
          <template v-if="auth.isLoggedIn">
            <router-link to="/profile" class="text-xs text-gray-400 hover:text-white transition">{{ auth.user?.username }}</router-link>
            <router-link v-if="auth.isAdmin" to="/admin" class="text-xs text-red-400/80 hover:text-red-400 transition">Admin</router-link>
            <button @click="auth.logout()" class="text-xs text-gray-600 hover:text-gray-300 transition">Logout</button>
          </template>
          <router-link v-else to="/login" class="text-xs text-gray-400 hover:text-white px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] transition">Login</router-link>
        </div>

        <button class="md:hidden p-1.5 rounded-lg hover:bg-white/5 transition" @click="menuOpen = !menuOpen">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              :d="menuOpen ? 'M6 18L18 6M6 6l12 12' : 'M4 6h16M4 12h16M4 18h16'" />
          </svg>
        </button>
      </div>

      <div v-if="menuOpen" class="md:hidden border-t border-white/[0.04] px-4 py-3 space-y-1 bg-[#0a0a14]/95 backdrop-blur-xl">
        <router-link to="/" class="block tab-link" @click="menuOpen = false">Home</router-link>
        <router-link to="/blog" class="block tab-link" @click="menuOpen = false">Blog</router-link>
        <router-link to="/music" class="block tab-link" @click="menuOpen = false">Music</router-link>
        <hr class="border-white/[0.04] my-2" />
        <template v-if="auth.isLoggedIn">
          <router-link to="/profile" class="block tab-link" @click="menuOpen = false">Profile</router-link>
          <router-link v-if="auth.isAdmin" to="/admin" class="block tab-link text-red-400" @click="menuOpen = false">Admin</router-link>
          <button @click="auth.logout(); menuOpen = false" class="block tab-link w-full text-left">Logout</button>
        </template>
        <router-link v-else to="/login" class="block tab-link" @click="menuOpen = false">Login</router-link>
      </div>
    </header>

    <main class="flex-1">
      <router-view />
    </main>

    <footer class="py-8 text-center border-t border-white/[0.04]">
      <p class="text-gray-700 text-xs">&copy; {{ new Date().getFullYear() }} Viste Lab</p>
    </footer>
  </div>
</template>
