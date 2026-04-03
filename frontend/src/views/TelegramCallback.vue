<script setup lang="ts">
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

onMounted(async () => {
  const q = route.query
  if (!q.id || !q.hash) {
    router.push('/login')
    return
  }

  try {
    const { data } = await api.post('/auth/telegram/callback', {
      id: Number(q.id),
      first_name: q.first_name || '',
      last_name: q.last_name || '',
      username: q.username || '',
      photo_url: q.photo_url || '',
      auth_date: Number(q.auth_date),
      hash: q.hash,
    })
    auth.setToken(data.token)
    await auth.fetchUser()
    router.push('/')
  } catch {
    router.push('/login')
  }
})
</script>

<template>
  <div class="flex items-center justify-center min-h-[60vh]">
    <p class="text-gray-400">Authenticating with Telegram...</p>
  </div>
</template>
