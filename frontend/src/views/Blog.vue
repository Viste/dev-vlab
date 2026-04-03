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
  if (page.value * limit < total.value) {
    page.value++
    load()
  }
}
function prevPage() {
  if (page.value > 1) {
    page.value--
    load()
  }
}
</script>

<template>
  <div class="max-w-3xl mx-auto px-4 py-12">
    <h1 class="text-3xl font-bold mb-8">Blog</h1>

    <div v-if="!posts.length" class="text-gray-500">No posts yet.</div>

    <div class="space-y-6">
      <router-link
        v-for="post in posts"
        :key="post.id"
        :to="{ name: 'blog-post', params: { slug: post.slug } }"
        class="block border border-gray-800 rounded-lg p-6 hover:border-purple-500 transition"
      >
        <h2 class="text-xl font-semibold hover:text-purple-400 transition">{{ post.title }}</h2>
        <p v-if="post.summary" class="text-gray-400 mt-2">{{ post.summary }}</p>
        <time class="text-xs text-gray-500 mt-2 block">{{ new Date(post.created_at).toLocaleDateString() }}</time>
      </router-link>
    </div>

    <div v-if="total > limit" class="flex gap-4 mt-8 justify-center">
      <button @click="prevPage" :disabled="page === 1" class="btn" :class="{ 'opacity-50': page === 1 }">Prev</button>
      <span class="text-gray-400 self-center">{{ page }}</span>
      <button @click="nextPage" :disabled="page * limit >= total" class="btn" :class="{ 'opacity-50': page * limit >= total }">Next</button>
    </div>
  </div>
</template>
