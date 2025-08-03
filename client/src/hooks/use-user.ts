import { useAuth } from "./useAuth";

export function useUser() {
  const { user, login, logout, register, isLoading, refreshUserData } = useAuth();
  
  return {
    user,
    login,
    logout,
    register,
    isLoading,
    refreshUserData,
    isAuthenticated: !!user,
  };
}