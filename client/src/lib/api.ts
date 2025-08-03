export async function apiRequest(
  method: string,
  url: string,
  data?: unknown,
): Promise<Response> {
  try {
    const response = await fetch(url, {
      method,
      headers: data ? { "Content-Type": "application/json" } : {},
      body: data ? JSON.stringify(data) : undefined,
    });

    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
      } catch {
        errorData = { error: `HTTP ${response.status} - ${response.statusText}` };
      }
      
      const error = new Error(errorData.error || `HTTP ${response.status}`);
      (error as any).status = response.status;
      (error as any).statusText = response.statusText;
      throw error;
    }

    return response;
  } catch (error) {
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('Network error: Unable to connect to server');
    }
    throw error;
  }
}

export async function apiGet<T>(url: string): Promise<T> {
  const response = await apiRequest("GET", url);
  try {
    return await response.json();
  } catch (error) {
    console.error('Failed to parse JSON response:', error);
    throw new Error('Invalid response format');
  }
}

export async function apiPost<T>(url: string, data: unknown): Promise<T> {
  const response = await apiRequest("POST", url, data);
  try {
    return await response.json();
  } catch (error) {
    console.error('Failed to parse JSON response:', error);
    throw new Error('Invalid response format');
  }
}

export async function apiPut<T>(url: string, data: unknown): Promise<T> {
  const response = await apiRequest("PUT", url, data);
  try {
    return await response.json();
  } catch (error) {
    console.error('Failed to parse JSON response:', error);
    throw new Error('Invalid response format');
  }
}

export async function apiDelete(url: string): Promise<void> {
  await apiRequest("DELETE", url);
}
