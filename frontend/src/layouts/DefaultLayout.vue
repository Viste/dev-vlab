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
    <header class="sticky top-0 z-50 pt-4 px-4">
      <div class="max-w-6xl mx-auto">
        <div class="flex items-center justify-between h-12 px-4 bg-gray-900/70 backdrop-blur-xl border border-gray-800/50 rounded-2xl">
          <router-link to="/" class="flex items-center gap-2 hover:opacity-80 transition">
            <img src="/favicon.svg" class="w-5 h-5" alt="V" />
            <span class="text-sm font-bold text-gray-200 hidden sm:inline">Viste Lab</span>
          </router-link>

          <nav class="hidden md:flex items-center bg-gray-800/40 rounded-xl p-1 gap-0.5">
            <router-link to="/" class="tab-link" active-class="tab-active" :class="{ 'tab-active': $route.path === '/' && $route.name === 'home' }">Home</router-link>
            <router-link to="/blog" class="tab-link" active-class="tab-active">Blog</router-link>
            <router-link to="/music" class="tab-link" active-class="tab-active">Music</router-link>
          </nav>

          <div class="hidden md:flex items-center gap-2">
            <a v-for="link in navLinks" :key="link.id" :href="link.url" target="_blank"
              class="text-xs text-gray-500 hover:text-gray-300 transition">{{ link.title }}</a>
            <template v-if="auth.isLoggedIn">
              <router-link to="/profile" class="tab-link-sm">{{ auth.user?.username }}</router-link>
              <router-link v-if="auth.isAdmin" to="/admin" class="text-xs text-red-700 hover:text-red-600 transition">Admin</router-link>
              <button @click="auth.logout()" class="text-xs text-gray-500 hover:text-gray-300 transition">Logout</button>
            </template>
            <router-link v-else to="/login" class="tab-link-sm">Login</router-link>
          </div>

          <button class="md:hidden p-1.5 rounded-lg hover:bg-gray-800/50 transition" @click="menuOpen = !menuOpen">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                :d="menuOpen ? 'M6 18L18 6M6 6l12 12' : 'M4 6h16M4 12h16M4 18h16'" />
            </svg>
          </button>
        </div>

        <div v-if="menuOpen" class="mt-2 bg-gray-900/90 backdrop-blur-xl border border-gray-800/50 rounded-2xl p-3 md:hidden space-y-1">
          <router-link to="/" class="block tab-link" @click="menuOpen = false">Home</router-link>
          <router-link to="/blog" class="block tab-link" @click="menuOpen = false">Blog</router-link>
          <router-link to="/music" class="block tab-link" @click="menuOpen = false">Music</router-link>
          <hr class="border-gray-800/50 my-2" />
          <template v-if="auth.isLoggedIn">
            <router-link to="/profile" class="block tab-link" @click="menuOpen = false">Profile</router-link>
            <router-link v-if="auth.isAdmin" to="/admin" class="block tab-link text-red-700" @click="menuOpen = false">Admin</router-link>
            <button @click="auth.logout(); menuOpen = false" class="block tab-link w-full text-left">Logout</button>
          </template>
          <router-link v-else to="/login" class="block tab-link" @click="menuOpen = false">Login</router-link>
        </div>
      </div>
    </header>

    <main class="flex-1">
      <router-view />
    </main>

    <footer class="py-8 text-center">
      <p class="text-gray-700 text-xs">&copy; {{ new Date().getFullYear() }} Viste Lab</p>
    </footer>
  </div>
</template>
