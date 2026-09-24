import getConfig from 'next/config';

const config = getConfig();

let apiUrl = process.env.NEXT_PUBLIC_API_URL;
if (config) {
  apiUrl = config?.serverRuntimeConfig?.apiUrl
}

export {
  apiUrl
}
