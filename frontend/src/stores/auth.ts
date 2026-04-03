import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../api/client'
import type { User } from '../api/types'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const token = ref<string | null>(localStorage.getItem('token'))

  const isLoggedIn = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.is_admin ?? false)

  async function fetchUser() {
    if (!token.value) return
    try {
      const { data } = await api.get<User>('/auth/me')
      user.value = data
    } catch {
      logout()
    }
  }

  function setToken(t: string) {
    token.value = t
    localStorage.setItem('token', t)
  }

  function logout() {
    token.value = null
    user.value = null
    localStorage.removeItem('token')
  }

  return { user, token, isLoggedIn, isAdmin, fetchUser, setToken, logout }
})
