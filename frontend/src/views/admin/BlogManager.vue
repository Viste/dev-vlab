<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import api from '../../api/client'
import type { BlogPost, PaginatedResponse } from '../../api/types'

const router = useRouter()
const posts = ref<BlogPost[]>([])
const total = ref(0)
const page = ref(1)

async function load() {
  const { data } = await api.get<PaginatedResponse<BlogPost>>('/admin/blog', { params: { page: page.value, limit: 20 } })
  posts.value = data.posts
  total.value = data.total
}

async function deletePost(id: number) {
  if (!confirm('Delete this post?')) return
  await api.delete(`/admin/blog/${id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-xl font-bold">Blog Posts</h1>
      <router-link to="/admin/blog/new" class="btn">New Post</router-link>
    </div>

    <div class="space-y-2">
      <div v-for="post in posts" :key="post.id" class="flex items-center justify-between bg-[#12121f] border border-gray-800/40 rounded-2xl p-4">
        <div>
          <span class="font-medium">{{ post.title }}</span>
          <span v-if="!post.published" class="ml-2 text-xs text-yellow-500 bg-yellow-500/10 px-2 py-0.5 rounded">Draft</span>
        </div>
        <div class="flex gap-2">
          <button @click="router.push(`/admin/blog/${post.id}/edit`)" class="btn-sm">Edit</button>
          <button @click="deletePost(post.id)" class="btn-sm-danger">Delete</button>
        </div>
      </div>
    </div>
  </div>
</template>
