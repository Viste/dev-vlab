<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ modelValue: number; readonly?: boolean; size?: 'sm' | 'md' }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: number): void }>()

const hover = ref(0)

function set(v: number) {
  if (props.readonly) return
  emit('update:modelValue', props.modelValue === v ? 0 : v)
}
</script>

<template>
  <div class="inline-flex items-center gap-0.5" @mouseleave="hover = 0">
    <button v-for="i in 5" :key="i" type="button" :disabled="readonly" :title="`${i}`"
      @click="set(i)" @mouseenter="!readonly && (hover = i)"
      class="transition disabled:cursor-default"
      :class="[
        size === 'sm' ? 'w-3.5 h-3.5' : 'w-5 h-5',
        (hover || modelValue) >= i ? 'text-amber-400' : 'text-gray-700',
        !readonly && 'hover:scale-110 cursor-pointer',
      ]">
      <svg viewBox="0 0 20 20" fill="currentColor" class="w-full h-full">
        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
      </svg>
    </button>
  </div>
</template>
