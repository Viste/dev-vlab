<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api from '../api/client'
import type { BlogPost } from '../api/types'

const route = useRoute()
const auth = useAuthStore()
const post = ref<BlogPost | null>(null)
const commentText = ref('')
const loading = ref(true)

async function load() {
  loading.value = true
  const { data } = await api.get<BlogPost>(`/blog/${route.params.slug}`)
  post.value = data
  loading.value = false
}

async function addComment() {
  if (!commentText.value.trim() || !post.value) return
  await api.post(`/blog/${post.value.slug}/comments`, { content: commentText.value })
  commentText.value = ''
  await load()
}

async function deleteComment(id: number) {
  await api.delete(`/blog/comments/${id}`)
  await load()
}

onMounted(load)
</script>

<template>
  <div class="max-w-3xl mx-auto px-4 py-12">
    <div v-if="loading" class="text-gray-500">Loading...</div>

    <article v-else-if="post">
      <img v-if="post.cover_url" :src="post.cover_url" :alt="post.title" class="w-full rounded-lg mb-6 max-h-80 object-cover" />
      <h1 class="text-4xl font-bold mb-2">{{ post.title }}</h1>
      <time class="text-sm text-gray-500">{{ new Date(post.created_at).toLocaleDateString() }}</time>

      <div class="prose prose-invert mt-8 max-w-none" v-html="post.content"></div>

      <section class="mt-12 border-t border-gray-800 pt-8">
        <h2 class="text-xl font-semibold mb-4">Comments ({{ post.comments?.length || 0 }})</h2>

        <form v-if="auth.isLoggedIn" @submit.prevent="addComment" class="mb-6">
          <textarea
            v-model="commentText"
            rows="3"
            placeholder="Write a comment..."
            class="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 text-sm focus:border-purple-500 focus:outline-none"
          ></textarea>
          <button type="submit" class="btn mt-2">Post Comment</button>
        </form>
        <p v-else class="text-gray-500 mb-6">
          <router-link to="/login" class="text-purple-400 hover:underline">Log in</router-link> to comment.
        </p>

        <div class="space-y-4">
          <div v-for="comment in post.comments" :key="comment.id" class="border border-gray-800 rounded-lg p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="font-medium text-sm">{{ comment.user.username }}</span>
              <div class="flex items-center gap-3">
                <time class="text-xs text-gray-500">{{ new Date(comment.created_at).toLocaleDateString() }}</time>
                <button
                  v-if="auth.user?.id === comment.user_id || auth.isAdmin"
                  @click="deleteComment(comment.id)"
                  class="text-xs text-red-400 hover:text-red-300"
                >Delete</button>
              </div>
            </div>
            <p class="text-sm text-gray-300">{{ comment.content }}</p>
          </div>
        </div>
      </section>
    </article>
  </div>
</template>
