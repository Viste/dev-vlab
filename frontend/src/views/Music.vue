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
  } catch { /* no active stream */ }
})
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 py-12">
    <h1 class="text-3xl font-bold mb-8">Music</h1>

    <div v-if="radio" class="mb-10 border border-purple-500/30 bg-purple-500/5 rounded-lg p-6">
      <h2 class="text-lg font-semibold text-purple-400 mb-3">{{ radio.title }}</h2>
      <audio controls :src="radio.stream_url" class="w-full"></audio>
    </div>

    <div class="flex gap-4 mb-6 border-b border-gray-800">
      <button
        @click="tab = 'releases'"
        class="pb-2 text-sm font-medium transition"
        :class="tab === 'releases' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-gray-400'"
      >Releases</button>
      <button
        @click="tab = 'demos'"
        class="pb-2 text-sm font-medium transition"
        :class="tab === 'demos' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-gray-400'"
      >Demos</button>
    </div>

    <div v-if="tab === 'releases'" class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div v-for="release in releases" :key="release.id" class="border border-gray-800 rounded-lg overflow-hidden">
        <img v-if="release.cover_url" :src="release.cover_url" :alt="release.title" class="w-full h-48 object-cover" />
        <div class="p-4">
          <h3 class="font-semibold">{{ release.title }}</h3>
          <p v-if="release.artist" class="text-sm text-gray-400">{{ release.artist }}</p>
          <div v-if="release.embed_url" class="mt-3">
            <iframe
              :src="release.embed_url"
              width="100%"
              height="166"
              frameborder="0"
              allow="autoplay"
              class="rounded"
            ></iframe>
          </div>
          <a v-if="release.release_url" :href="release.release_url" target="_blank"
            class="inline-block mt-3 text-sm text-purple-400 hover:underline">Listen &rarr;</a>
        </div>
      </div>
    </div>

    <div v-if="tab === 'demos'" class="space-y-4">
      <div v-for="demo in demos" :key="demo.id" class="border border-gray-800 rounded-lg p-4">
        <h3 class="font-semibold mb-1">{{ demo.title }}</h3>
        <p v-if="demo.description" class="text-sm text-gray-400 mb-3">{{ demo.description }}</p>
        <div v-if="demo.embed_url" class="mb-3">
          <iframe
            :src="demo.embed_url"
            width="100%"
            height="166"
            frameborder="0"
            allow="autoplay"
            class="rounded"
          ></iframe>
        </div>
        <audio v-else-if="demo.file_url" controls :src="demo.file_url" class="w-full"></audio>
      </div>
    </div>
  </div>
</template>
