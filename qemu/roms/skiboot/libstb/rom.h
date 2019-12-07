/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ROM_H
#define __ROM_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "container.h"

struct rom_driver_ops {
	const char* name;
	int  (*verify)(void *container);
	void (*sha512)(const uint8_t *data, size_t len, uint8_t *digest);
	void (*cleanup)(void);
};

/*
 * Load a compatible driver to access the functions of the
 * verification code flashed in the secure ROM
 */
extern struct rom_driver_ops* rom_init(const struct dt_node *node);

/*
 * Set the rom driver that will be used
 */
extern void rom_set_driver(struct rom_driver_ops *driver);

#endif /* __ROM_H */
