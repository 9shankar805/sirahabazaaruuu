import { QueryClient, QueryFunction } from "@tanstack/react-query";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(
  url: string,
  options?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  }
): Promise<Response> {
  const res = await fetch(url, {
    method: options?.method || "GET",
    headers: options?.headers || {},
    body: options?.body,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const res = await fetch(queryKey[0] as string, {
      credentials: "include",
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: 1,
    },
    mutations: {
      retry: false,
    },
  },
});

// Handle QueryClient errors globally
queryClient.setMutationDefaults(['*'], {
  onError: (error: any) => {
    console.error('Global mutation error:', error);
  },
});

// Note: Query defaults error handling removed as it's not supported in current TanStack Query version

// Helper functions for API requests
export async function apiGet<T = any>(url: string): Promise<T> {
  const response = await apiRequest(url);
  return response.json();
}

export async function apiPost(url: string, data: any): Promise<any> {
  const response = await apiRequest(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return response.json();
}

export async function apiPut(url: string, data: any): Promise<any> {
  const response = await apiRequest(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return response.json();
}

export async function apiDelete(url: string): Promise<any> {
  const response = await apiRequest(url, {
    method: "DELETE",
  });
  return response.json();
}

export async function apiPatch(url: string, data: any): Promise<any> {
  const response = await apiRequest(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  return response.json();
}