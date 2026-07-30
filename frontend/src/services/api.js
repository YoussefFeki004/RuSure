import axios from 'axios';

const API_BASE = '/api';

const handleResponse = async (promise) => {
  try {
    const response = await promise;
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data.error || error.response.statusText);
    }
    throw new Error(error.message || 'Network error');
  }
};

export const getHistory = () => {
  return handleResponse(axios.get(`${API_BASE}/history`));
};

export const getHistoryDetail = (scanId) => {
  return handleResponse(axios.get(`${API_BASE}/history/${scanId}`));
};

export const uploadFiles = (scannerType, xmlFile, payloadsFile) => {
  const formData = new FormData();
  formData.append(`${scannerType}_xml`, xmlFile);
  if (payloadsFile) {
    formData.append(`${scannerType}_payloads_txt`, payloadsFile);
  }
  return handleResponse(axios.post(`${API_BASE}/upload`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }));
};

export const runScan = (scannerType, scanId, config) => {
  const formData = new FormData();
  formData.append('scan_id', scanId);
  formData.append('cookie', config.cookie || '');
  formData.append('headers', config.headers || '');
  formData.append('proxy', config.proxy || '');
  formData.append('base_url', config.baseUrl || '');
  formData.append('payloads_path', config.payloadsPath || '');
  formData.append('dbms', config.dbms || '');
  
  Object.entries(config.options || {}).forEach(([key, value]) => {
    if (value) {
      formData.append(key, 'on');
    }
  });
  
  return handleResponse(axios.post(`${API_BASE}/run/${scannerType}`, formData));
};

export const getStatus = (scanId, scannerType) => {
  return handleResponse(axios.get(`${API_BASE}/status/${scanId}/${scannerType}`));
};

export const getResults = (scanId, scannerType) => {
  return handleResponse(axios.get(`${API_BASE}/results/${scanId}/${scannerType}`));
};

export const deleteScan = (scanId) => {
  return handleResponse(axios.delete(`${API_BASE}/delete_scan/${scanId}`));
};

export const deleteAllScans = () => {
  return handleResponse(axios.delete(`${API_BASE}/delete_all_scans`));
};

export const getLogs = (scanId, scannerType) => {
  return handleResponse(axios.get(`${API_BASE}/logs/${scanId}/${scannerType}`));
};

export const getPayloads = (scanId, scannerType) => {
  return handleResponse(axios.get(`${API_BASE}/payloads/${scanId}/${scannerType}`));
};
