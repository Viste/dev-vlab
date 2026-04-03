<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import api from '../../api/client'

const route = useRoute()
const router = useRouter()
const isEdit = !!route.params.id
const saving = ref(false)

const form = ref({
  title: '',
  content: '',
  summary: '',
  cover_url: '',
  published: false,
})

onMounted(async () => {
  if (isEdit) {
    const { data } = await api.get('/admin/blog', { params: { limit: 100 } })
    const post = data.posts.find((p: any) => p.id === Number(route.params.id))
    if (post) {
      form.value = {
        title: post.title,
        content: post.content,
        summary: post.summary || '',
        cover_url: post.cover_url || '',
        published: post.published,
      }
    }
  }
})

async function save() {
  saving.value = true
  try {
    if (isEdit) {
      await api.put(`/admin/blog/${route.params.id}`, form.value)
    } else {
      await api.post('/admin/blog', form.value)
    }
    router.push('/admin/blog')
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold mb-6">{{ isEdit ? 'Edit Post' : 'New Post' }}</h1>

    <form @submit.prevent="save" class="space-y-4 max-w-3xl">
      <div>
        <label class="label">Title</label>
        <input v-model="form.title" class="input" required />
      </div>
      <div>
        <label class="label">Summary</label>
        <input v-model="form.summary" class="input" />
      </div>
      <div>
        <label class="label">Cover URL</label>
        <input v-model="form.cover_url" class="input" />
      </div>
      <div>
        <label class="label">Content (HTML)</label>
        <textarea v-model="form.content" rows="15" class="input font-mono text-sm"></textarea>
      </div>
      <div class="flex items-center gap-2">
        <input type="checkbox" v-model="form.published" id="published" class="rounded" />
        <label for="published" class="text-sm">Published</label>
      </div>
      <div class="flex gap-3">
        <button type="submit" class="btn" :disabled="saving">{{ saving ? 'Saving...' : 'Save' }}</button>
        <router-link to="/admin/blog" class="btn-secondary">Cancel</router-link>
      </div>
    </form>
  </div>
</template>
