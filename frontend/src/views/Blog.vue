<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import type { BlogPost, PaginatedResponse } from '../api/types'

const posts = ref<BlogPost[]>([])
const total = ref(0)
const page = ref(1)
const limit = 10

async function load() {
  const { data } = await api.get<PaginatedResponse<BlogPost>>('/blog', {
    params: { page: page.value, limit },
  })
  posts.value = data.posts
  total.value = data.total
}

onMounted(load)

function nextPage() {
  if (page.value * limit < total.value) { page.value++; load() }
}
function prevPage() {
  if (page.value > 1) { page.value--; load() }
}
</script>

<template>
  <div class="max-w-4xl mx-auto px-4 py-10">
    <div class="bento-card p-8 mb-6">
      <p class="text-sm text-red-700 font-mono mb-2">blog</p>
      <h1 class="text-3xl font-bold">Thoughts &amp; Notes</h1>
      <p class="text-gray-400 mt-2">Writing about tech, music, and everything in between.</p>
    </div>

    <div v-if="!posts.length" class="bento-card p-8 text-center text-gray-500">No posts yet.</div>

    <div class="space-y-3">
      <router-link
        v-for="post in posts" :key="post.id"
        :to="{ name: 'blog-post', params: { slug: post.slug } }"
        class="bento-card p-6 block group hover:border-red-800/30 transition">
        <div class="flex items-start justify-between gap-4">
          <div>
            <h2 class="text-lg font-semibold group-hover:text-red-700 transition">{{ post.title }}</h2>
            <p v-if="post.summary" class="text-gray-400 text-sm mt-1.5 line-clamp-2">{{ post.summary }}</p>
          </div>
          <time class="text-xs text-gray-600 shrink-0 mt-1">{{ new Date(post.created_at).toLocaleDateString() }}</time>
        </div>
      </router-link>
    </div>

    <div v-if="total > limit" class="flex gap-4 mt-6 justify-center">
      <button @click="prevPage" :disabled="page === 1" class="btn-secondary" :class="{ 'opacity-30': page === 1 }">Prev</button>
      <span class="text-gray-500 self-center text-sm">{{ page }}</span>
      <button @click="nextPage" :disabled="page * limit >= total" class="btn-secondary" :class="{ 'opacity-30': page * limit >= total }">Next</button>
    </div>
  </div>
</template>
