<script setup lang="ts">
import api from '../api/client'

async function loginVK() {
  const { data } = await api.get<{ url: string }>('/auth/vk')
  window.location.href = data.url
}

const telegramBotName = import.meta.env.VITE_TELEGRAM_BOT_NAME || 'vlab_bot'
const origin = window.location.origin
</script>

<template>
  <div class="max-w-md mx-auto px-4 py-24">
    <h1 class="text-3xl font-bold mb-8 text-center">Login</h1>

    <div class="space-y-4">
      <button
        @click="loginVK"
        class="w-full flex items-center justify-center gap-3 bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition"
      >
        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12.785 16.241s.288-.032.436-.194c.136-.148.132-.427.132-.427s-.02-1.304.587-1.496c.598-.188 1.368 1.259 2.183 1.815.616.42 1.084.328 1.084.328l2.175-.03s1.14-.07.6-.964c-.044-.073-.314-.661-1.618-1.869-1.366-1.265-1.183-1.06.462-3.246.999-1.33 1.398-2.142 1.273-2.489-.12-.332-.854-.244-.854-.244l-2.45.015s-.182-.025-.317.056c-.131.079-.216.263-.216.263s-.389 1.036-.906 1.917c-1.093 1.86-1.53 1.96-1.708 1.843-.415-.27-.312-1.088-.312-1.668 0-1.813.275-2.568-.534-2.765-.269-.065-.466-.108-1.154-.115-.882-.009-1.628.003-2.05.209-.281.138-.498.443-.366.46.163.022.533.1.729.365.253.342.244 1.108.244 1.108s.145 2.133-.34 2.397c-.332.181-.788-.189-1.766-1.884-.502-.869-.88-1.829-.88-1.829s-.073-.178-.203-.274c-.157-.116-.377-.153-.377-.153l-2.327.015s-.35.01-.478.161c-.114.135-.009.413-.009.413s1.83 4.282 3.902 6.442c1.9 1.98 4.055 1.849 4.055 1.849h.977z" />
        </svg>
        Sign in with VK
      </button>

      <div class="text-center text-gray-500 text-sm">or</div>

      <div class="flex justify-center">
        <script
          async
          :src="`https://telegram.org/js/telegram-widget.js?22`"
          :data-telegram-login="telegramBotName"
          data-size="large"
          data-radius="8"
          :data-auth-url="`${origin}/auth/telegram/callback`"
          data-request-access="write"
        ></script>
      </div>
    </div>
  </div>
</template>
