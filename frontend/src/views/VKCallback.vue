<script setup lang="ts">
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

onMounted(async () => {
  const code = route.query.code as string
  const state = route.query.state as string
  const deviceId = route.query.device_id as string || ''

  if (!code || !state) {
    router.push('/login')
    return
  }

  try {
    const { data } = await api.post('/auth/vk/callback', { code, state, device_id: deviceId })
    auth.setToken(data.token)
    await auth.fetchUser()
    router.push((route.query.redirect as string) || '/')
  } catch {
    router.push('/login')
  }
})
</script>

<template>
  <div class="flex items-center justify-center min-h-[60vh]">
    <p class="text-gray-400">Authenticating with VK...</p>
  </div>
</template>
