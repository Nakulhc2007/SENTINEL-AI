import { create } from 'zustand'
import { Org } from './api'

interface AppState {
  selectedOrg: Org | null
  setOrg: (org: Org | null) => void
  orgs: Org[]
  setOrgs: (orgs: Org[]) => void
}

export const useAppStore = create<AppState>(set => ({
  selectedOrg: null,
  setOrg: org => set({ selectedOrg: org }),
  orgs: [],
  setOrgs: orgs => set({ orgs }),
}))
