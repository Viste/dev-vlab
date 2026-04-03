<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import type { MusicRelease, MusicDemo, RadioStream } from '../api/types'

const releases = ref<MusicRelease[]>([])
const demos = ref<MusicDemo[]>([])
const radio = ref<RadioStream | null>(null)
const tab = ref<'releases' | 'demos'>('releases')

onMounted(async () => {
  const [relRes, demoRes] = await Promise.all([
    api.get<MusicRelease[]>('/music/releases'),
    api.get<MusicDemo[]>('/music/demos'),
  ])
  releases.value = relRes.data
  demos.value = demoRes.data
  try {
    const { data } = await api.get<RadioStream>('/music/radio')
    radio.value = data
  } catch { /* no stream */ }
})
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 py-10">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
      <div class="md:col-span-2 bento-card p-8">
        <p class="text-sm text-red-500 font-mono mb-2">music</p>
        <h1 class="text-3xl font-bold">Music &amp; Sound</h1>
        <p class="text-gray-400 mt-2">Releases, demos, and live radio streams.</p>
      </div>

      <div v-if="radio" class="bento-card p-6 flex flex-col justify-between border-red-500/20">
        <div>
          <div class="flex items-center gap-2 mb-2">
            <span class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
            <span class="text-sm font-semibold text-red-500">LIVE</span>
          </div>
          <h2 class="font-bold">{{ radio.title }}</h2>
        </div>
        <audio controls :src="radio.stream_url" class="w-full mt-4"></audio>
      </div>
      <div v-else class="bento-card p-6 flex items-center justify-center text-gray-600 text-sm">
        No live stream right now
      </div>
    </div>

    <div class="flex gap-2 mb-6">
      <button @click="tab = 'releases'"
        class="px-4 py-2 rounded-xl text-sm font-medium transition"
        :class="tab === 'releases' ? 'bg-red-700 text-white' : 'bg-gray-800/60 text-gray-400 hover:text-white'">
        Releases
      </button>
      <button @click="tab = 'demos'"
        class="px-4 py-2 rounded-xl text-sm font-medium transition"
        :class="tab === 'demos' ? 'bg-red-700 text-white' : 'bg-gray-800/60 text-gray-400 hover:text-white'">
        Demos
      </button>
    </div>

    <div v-if="tab === 'releases'" class="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
      <div v-for="release in releases" :key="release.id" class="bento-card overflow-hidden">
        <img v-if="release.cover_url" :src="release.cover_url" :alt="release.title" class="w-full h-44 object-cover" />
        <div class="p-4">
          <h3 class="font-semibold">{{ release.title }}</h3>
          <p v-if="release.artist" class="text-sm text-gray-500">{{ release.artist }}</p>
          <div v-if="release.embed_url" class="mt-3">
            <iframe :src="release.embed_url" width="100%" height="166" frameborder="0" allow="autoplay" class="rounded-lg"></iframe>
          </div>
          <a v-if="release.release_url" :href="release.release_url" target="_blank"
            class="inline-block mt-3 text-sm text-red-500 hover:underline">Listen &rarr;</a>
        </div>
      </div>
      <div v-if="!releases.length" class="md:col-span-3 bento-card p-8 text-center text-gray-600">No releases yet.</div>
    </div>

    <div v-if="tab === 'demos'" class="space-y-3">
      <div v-for="demo in demos" :key="demo.id" class="bento-card p-5">
        <h3 class="font-semibold mb-1">{{ demo.title }}</h3>
        <p v-if="demo.description" class="text-sm text-gray-500 mb-3">{{ demo.description }}</p>
        <div v-if="demo.embed_url" class="mb-3">
          <iframe :src="demo.embed_url" width="100%" height="166" frameborder="0" allow="autoplay" class="rounded-lg"></iframe>
        </div>
        <audio v-else-if="demo.file_url" controls :src="demo.file_url" class="w-full"></audio>
      </div>
      <div v-if="!demos.length" class="bento-card p-8 text-center text-gray-600">No demos yet.</div>
    </div>
  </div>
</template>
