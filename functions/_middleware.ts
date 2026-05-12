import { setEnv } from './_shared/dataSources'

export const onRequest: PagesFunction = async (ctx) => {
  // Pass environment variables (secrets) to the data source module
  setEnv(ctx.env)
  return ctx.next()
}
