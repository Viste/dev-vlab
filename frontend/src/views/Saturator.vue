<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'

const version = ref('')
const urlMac = ref('')
const urlWin = ref('')
const changelog = ref('')
const loading = ref(true)

onMounted(async () => {
  try {
    const { data } = await api.get('/saturator/version')
    version.value = data.version
    urlMac.value = data.url_mac
    urlWin.value = data.url_win
    changelog.value = data.changelog
  } catch { /* no release */ }
  loading.value = false
})
</script>

<template>
  <div class="max-w-4xl mx-auto px-4 py-10">
    <div class="card-dark p-8 md:p-10 mb-6 relative overflow-hidden">
      <div class="absolute top-0 right-0 w-72 h-72 bg-red-500/5 rounded-full blur-3xl -mr-24 -mt-24"></div>
      <div class="relative">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-400/10 text-emerald-400 text-xs font-mono mb-5" v-if="version">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          v{{ version }}
        </div>
        <h1 class="text-4xl md:text-5xl font-bold mb-3">Saturator</h1>
        <p class="text-gray-400 text-base max-w-lg">
          Audio saturator plugin. Adds warmth, harmonics, and grit to your sound.
        </p>
      </div>
    </div>

    <div v-if="loading" class="card-dark p-8 text-center text-gray-500">Loading...</div>

    <template v-else-if="version">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <a v-if="urlMac" :href="urlMac"
          class="card-dark p-6 flex items-center gap-4 group hover:border-white/10 transition">
          <div class="w-12 h-12 rounded-xl bg-blue-400/10 flex items-center justify-center shrink-0">
            <svg class="w-6 h-6 text-blue-400" fill="currentColor" viewBox="0 0 24 24">
              <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
            </svg>
          </div>
          <div>
            <div class="font-semibold group-hover:text-white transition">Download for Mac</div>
            <div class="text-xs text-gray-500">macOS (Apple Silicon)</div>
          </div>
          <svg class="w-5 h-5 text-gray-700 group-hover:text-blue-400 transition ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
          </svg>
        </a>

        <a v-if="urlWin" :href="urlWin"
          class="card-dark p-6 flex items-center gap-4 group hover:border-white/10 transition">
          <div class="w-12 h-12 rounded-xl bg-cyan-400/10 flex items-center justify-center shrink-0">
            <svg class="w-6 h-6 text-cyan-400" fill="currentColor" viewBox="0 0 24 24">
              <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
            </svg>
          </div>
          <div>
            <div class="font-semibold group-hover:text-white transition">Download for Windows</div>
            <div class="text-xs text-gray-500">.exe installer</div>
          </div>
          <svg class="w-5 h-5 text-gray-700 group-hover:text-cyan-400 transition ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
          </svg>
        </a>
      </div>

      <div v-if="changelog" class="card-dark p-6">
        <h2 class="text-lg font-bold mb-3">Changelog</h2>
        <div class="text-sm text-gray-400 leading-relaxed whitespace-pre-line">{{ changelog }}</div>
      </div>
    </template>

    <div v-else class="card-dark p-8 text-center text-gray-500">No releases yet.</div>
  </div>
</template>
