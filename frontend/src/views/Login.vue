<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function loginPassword() {
  error.value = ''
  loading.value = true
  try {
    const { data } = await api.post('/auth/login', { username: username.value, password: password.value })
    auth.setToken(data.token)
    await auth.fetchUser()
    router.push((route.query.redirect as string) || '/')
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Login failed'
  } finally {
    loading.value = false
  }
}

async function loginVK() {
  const { data } = await api.get<{ url: string }>('/auth/vk')
  window.location.href = data.url
}

onMounted(() => {
  const container = document.getElementById('telegram-login')
  if (container) {
    const script = document.createElement('script')
    script.src = 'https://telegram.org/js/telegram-widget.js?22'
    script.setAttribute('data-telegram-login', 'stalinfollower_bot')
    script.setAttribute('data-size', 'large')
    script.setAttribute('data-radius', '12')
    script.setAttribute('data-auth-url', `${window.location.origin}/auth/telegram/callback`)
    script.setAttribute('data-request-access', 'write')
    script.async = true
    container.appendChild(script)
  }
})
</script>

<template>
  <div class="max-w-md mx-auto px-4 py-16">
    <div class="bento-card p-8">
      <div class="text-center mb-8">
        <img src="/favicon.svg" class="w-10 h-10 mx-auto mb-3" alt="V" />
        <h1 class="text-2xl font-bold mt-2">Welcome back</h1>
        <p class="text-gray-500 text-sm mt-1">Sign in to Viste Lab</p>
      </div>

      <form @submit.prevent="loginPassword" class="space-y-3 mb-6">
        <input v-model="username" placeholder="Username" class="input" required autocomplete="username" />
        <input v-model="password" type="password" placeholder="Password" class="input" required autocomplete="current-password" />
        <p v-if="error" class="text-red-600 text-sm">{{ error }}</p>
        <button type="submit" class="btn w-full" :disabled="loading">
          {{ loading ? 'Signing in...' : 'Sign in' }}
        </button>
      </form>

      <div class="relative my-6">
        <div class="absolute inset-0 flex items-center"><div class="w-full border-t border-gray-800"></div></div>
        <div class="relative flex justify-center"><span class="bg-gray-900/60 px-3 text-xs text-gray-600">or continue with</span></div>
      </div>

      <div class="space-y-3">
        <button @click="loginVK"
          class="w-full flex items-center justify-center gap-3 bg-blue-600/90 hover:bg-blue-600 text-white font-medium py-3 px-4 rounded-xl transition text-sm">
          <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12.785 16.241s.288-.032.436-.194c.136-.148.132-.427.132-.427s-.02-1.304.587-1.496c.598-.188 1.368 1.259 2.183 1.815.616.42 1.084.328 1.084.328l2.175-.03s1.14-.07.6-.964c-.044-.073-.314-.661-1.618-1.869-1.366-1.265-1.183-1.06.462-3.246.999-1.33 1.398-2.142 1.273-2.489-.12-.332-.854-.244-.854-.244l-2.45.015s-.182-.025-.317.056c-.131.079-.216.263-.216.263s-.389 1.036-.906 1.917c-1.093 1.86-1.53 1.96-1.708 1.843-.415-.27-.312-1.088-.312-1.668 0-1.813.275-2.568-.534-2.765-.269-.065-.466-.108-1.154-.115-.882-.009-1.628.003-2.05.209-.281.138-.498.443-.366.46.163.022.533.1.729.365.253.342.244 1.108.244 1.108s.145 2.133-.34 2.397c-.332.181-.788-.189-1.766-1.884-.502-.869-.88-1.829-.88-1.829s-.073-.178-.203-.274c-.157-.116-.377-.153-.377-.153l-2.327.015s-.35.01-.478.161c-.114.135-.009.413-.009.413s1.83 4.282 3.902 6.442c1.9 1.98 4.055 1.849 4.055 1.849h.977z" />
          </svg>
          VK
        </button>
        <div id="telegram-login" class="flex justify-center"></div>
      </div>
    </div>
  </div>
</template>
