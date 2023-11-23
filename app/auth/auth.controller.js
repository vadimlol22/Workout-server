import { faker } from '@faker-js/faker'
import { prisma } from '../prisma.js'
import asyncHandler from 'express-async-handler'
import { hash, verify } from 'argon2'
import { generateToken } from './generate-token.js'
import { UserFields } from '../utils/user.utils.js'

// @desc    Auth user
// @route   POST /api/auth/login
// @access  Public

export const authUser = async (req, res) => {
	const { email, password } = req.body

	const user = await prisma.user.findUnique({
		where: {
			email
		}
	})

	const isValidPassword = await verify(user.password, password)

	if (user && isValidPassword) {
		const token = generateToken(user.id)
		res.json({ user, token })
	} else {
		res.status(401)
		throw new Error('Email and password are not correct')
	}
}

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
export const registerUser = asyncHandler(async (req, res) => {
	const { email, password } = req.body

	const isHaveUser = await prisma.user.findUnique({
		where: {
			email
		}
	})

	if (isHaveUser) {
		res.status(400)
		throw new Error('User already exists')
	}

	const user = await prisma.user.create({
		data: {
			email,
			password: await hash(password),
			name: faker.internet.userName()
		},
		select: UserFields
	})

	const token = generateToken(user.id)

	res.json({ user, token })
})
