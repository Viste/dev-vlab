<script setup lang="ts">
import { ref, onMounted } from 'vue'
import api from '../api/client'
import type { Project, NavigationLink } from '../api/types'

const projects = ref<Project[]>([])
const links = ref<NavigationLink[]>([])

onMounted(async () => {
  const [projRes, linkRes] = await Promise.all([
    api.get<Project[]>('/projects').catch(() => ({ data: [] })),
    api.get<NavigationLink[]>('/nav-links').catch(() => ({ data: [] })),
  ])
  projects.value = projRes.data
  links.value = linkRes.data
})
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 py-10">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">

      <div class="md:col-span-2 bento-card p-8">
        <p class="text-sm text-red-500 font-mono mb-4">hello world</p>
        <h1 class="text-4xl md:text-5xl font-bold leading-tight mb-4">
          Site Reliability Engineer.<br/>
          <span class="text-red-500">Music Producer.</span>
        </h1>
        <p class="text-gray-400 text-lg max-w-xl mt-4">
          Building and maintaining infrastructure, CI/CD pipelines, and keeping things alive in production.
          Writing Go, Python, and C/C++ when needed. Making drum &amp; bass and hip-hop beats in spare time.
        </p>
        <div class="flex flex-wrap gap-2 mt-6">
          <span class="tag">SRE</span>
          <span class="tag">GO</span>
          <span class="tag">PYTHON</span>
          <span class="tag">C/C++</span>
          <span class="tag">KUBERNETES</span>
          <span class="tag">DEVOPS</span>
          <span class="tag">D&amp;B</span>
          <span class="tag">HIP-HOP</span>
        </div>
      </div>

      <div class="bento-card p-6 flex flex-col justify-between">
        <div>
          <div class="text-3xl mb-3">&#9993;</div>
          <h2 class="text-xl font-bold mb-2">Get in touch</h2>
          <p class="text-gray-400 text-sm">Want to collaborate or just say hi?</p>
        </div>
        <div class="mt-6 space-y-2">
          <a v-for="link in links" :key="link.id" :href="link.url" target="_blank"
            class="flex items-center gap-2 text-sm text-gray-300 hover:text-red-400 transition">
            <span v-if="link.icon">{{ link.icon }}</span>
            <span>{{ link.title }}</span>
          </a>
          <a href="https://t.me/viste" target="_blank"
            class="flex items-center gap-2 text-sm text-gray-300 hover:text-red-400 transition">
            Telegram &rarr;
          </a>
        </div>
      </div>

      <div class="bento-card p-6 cursor-pointer group" @click="$router.push('/music')">
        <div class="flex items-center justify-between mb-4">
          <div class="text-2xl">&#9835;</div>
          <svg class="w-5 h-5 text-gray-700 group-hover:text-red-500 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
        </div>
        <h2 class="text-xl font-bold mb-1">Music &amp; Sound</h2>
        <p class="text-gray-400 text-sm">Releases, demos, radio streams.</p>
      </div>

      <div class="bento-card p-6 cursor-pointer group" @click="$router.push('/blog')">
        <div class="flex items-center justify-between mb-4">
          <div class="text-2xl">&#9998;</div>
          <svg class="w-5 h-5 text-gray-700 group-hover:text-red-500 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
        </div>
        <h2 class="text-xl font-bold mb-1">Blog</h2>
        <p class="text-gray-400 text-sm">Thoughts on tech, music, and life.</p>
      </div>

      <div class="bento-card p-6 flex flex-col justify-center items-center text-center">
        <div class="text-4xl font-bold text-red-500 mb-1 font-mono">&lt;/&gt;</div>
        <p class="text-gray-400 text-sm mt-2">Open source</p>
        <a href="https://github.com/Viste" target="_blank"
          class="mt-3 text-sm text-red-400 hover:underline">GitHub &rarr;</a>
      </div>

      <div v-if="projects.length" class="md:col-span-3 bento-card p-6">
        <h2 class="text-xl font-bold mb-4">Projects</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <a v-for="project in projects" :key="project.id"
            :href="project.project_url" target="_blank"
            class="group flex gap-4 p-4 rounded-xl bg-gray-800/30 hover:bg-gray-800/60 transition border border-transparent hover:border-gray-700/50">
            <img v-if="project.image_url" :src="project.image_url" :alt="project.title"
              class="w-12 h-12 rounded-lg object-cover shrink-0" />
            <div>
              <h3 class="font-semibold group-hover:text-red-400 transition">{{ project.title }}</h3>
              <p v-if="project.description" class="text-sm text-gray-500 mt-0.5">{{ project.description }}</p>
            </div>
          </a>
        </div>
      </div>

    </div>
  </div>
</template>
