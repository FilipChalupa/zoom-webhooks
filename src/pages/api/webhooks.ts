import crypto from 'crypto'
import type { NextApiRequest, NextApiResponse } from 'next'

const { ZOOM_WEBHOOK_SECRET_TOKEN = '' } = process.env

type Data =
	| {
			plainToken: string
			encryptedToken: string
	  }
	| {
			error: string
	  }

export default function handler(
	request: NextApiRequest,
	response: NextApiResponse<Data>,
) {
	const data = request.body

	if (data.event === 'endpoint.url_validation') {
		const hashForValidate = crypto
			.createHmac('sha256', ZOOM_WEBHOOK_SECRET_TOKEN)
			.update(request.body.payload.plainToken)
			.digest('hex')

		response.status(200).json({
			plainToken: request.body.payload.plainToken,
			encryptedToken: hashForValidate,
		})
		return
	}

	response.status(400).json({ error: 'Unknown request' })
}
