<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import type { Project } from '../api/types'

const projects = ref<Project[]>([])

onMounted(async () => {
  const { data } = await api.get<Project[]>('/projects')
  projects.value = data
})
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 py-12">
    <section class="text-center mb-16">
      <h1 class="text-5xl font-bold mb-4">Hey, I'm <span class="text-purple-400">Viste</span></h1>
      <p class="text-xl text-gray-400 max-w-2xl mx-auto">
        Developer, music producer, and all-around creative tinkerer.
      </p>
    </section>

    <section v-if="projects.length">
      <h2 class="text-2xl font-bold mb-6">Projects</h2>
      <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        <a
          v-for="project in projects"
          :key="project.id"
          :href="project.project_url"
          target="_blank"
          class="group block border border-gray-800 rounded-lg overflow-hidden hover:border-purple-500 transition"
        >
          <img
            v-if="project.image_url"
            :src="project.image_url"
            :alt="project.title"
            class="w-full h-48 object-cover"
          />
          <div class="p-4">
            <h3 class="font-semibold group-hover:text-purple-400 transition">{{ project.title }}</h3>
            <p v-if="project.description" class="text-sm text-gray-400 mt-1">{{ project.description }}</p>
          </div>
        </a>
      </div>
    </section>
  </div>
</template>
