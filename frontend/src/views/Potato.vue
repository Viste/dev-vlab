<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import icon from '../assets/potato.png'

const { t } = useI18n()
const abis = ['arm64', 'armv7', 'universal'] as const
type ABI = typeof abis[number]
interface Release {
  versionName: string
  versionCode: number
  artifacts: Record<ABI, { sha256: string; size: number }>
}
const release = ref<Release>()
const loading = ref(true)
async function load() {
  loading.value = true
  try {
    const res = await fetch('/api/potato/version')
    if (!res.ok) throw Error()
    const r: Release = await res.json()
    if (!Number.isSafeInteger(r.versionCode) || r.versionCode <= 0 || !/^\d+\.\d+\.\d+$/.test(r.versionName)
      || !abis.every(a => /^[0-9a-f]{64}$/.test(r.artifacts[a].sha256) && r.artifacts[a].size > 0)) throw Error()
    release.value = r
  } catch { release.value = undefined }
  finally { loading.value = false }
}
function url(r: Release, abi: ABI) {
  return `/api/potato/releases/${r.versionCode}/potato-${abi}-${r.artifacts[abi].sha256}.apk`
}
onMounted(load)
</script>
<template>
  <main class="max-w-xl mx-auto px-5 py-12 sm:py-20">
    <section class="card-dark p-7 sm:p-10">
      <img :src="icon" alt="" width="80" height="80" class="mb-5">
      <h1 class="text-4xl font-bold text-white">Potato</h1>
      <p class="mt-2 text-gray-400">{{ t('potato.subtitle') }}</p>
      <p v-if="loading" role="status" class="mt-8">{{ t('potato.loading') }}</p>
      <template v-else-if="release">
        <p class="mt-7 mb-3 font-mono text-sm text-gray-400">{{ t('potato.version') }} {{ release.versionName }}</p>
        <a :href="url(release, 'arm64')" class="inline-flex rounded-lg bg-white px-5 py-3 font-semibold text-black">
          {{ t('potato.download') }} · {{ Math.ceil(release.artifacts.arm64.size / 1048576) }} MiB
        </a>
        <p class="mt-2 text-sm text-gray-400">{{ t('potato.arm64') }}</p>
        <details class="mt-7 border-t border-white/10 pt-4">
          <summary class="cursor-pointer">{{ t('potato.other') }}</summary>
          <a v-for="abi in (['armv7', 'universal'] as const)" :key="abi" :href="url(release, abi)"
            class="block mt-4 underline">{{ t('potato.' + abi) }} · {{ Math.ceil(release.artifacts[abi].size / 1048576) }} MiB</a>
        </details>
      </template>
      <div v-else class="mt-8" role="status">
        <p>{{ t('potato.error') }}</p><button class="mt-3 underline" @click="load">{{ t('potato.retry') }}</button>
      </div>
    </section>
  </main>
</template>
