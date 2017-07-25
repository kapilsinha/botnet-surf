"""
Contains various metrics for the model
"""
import numpy as np
import keras.backend as K

'''
Counts the proportion of true positives to total actual positives
'''
def true_positives(y_true, y_pred):
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_pos = K.round(K.clip(y_true, 0, 1))
    true_positives = K.sum(y_pos * y_pred_pos)
    return true_positives

'''
Counts the proportion of true negatives to total actual negatives
'''
def true_negatives(y_true, y_pred):
    y_pred_neg = 1 - K.round(K.clip(y_pred, 0, 1))
    y_neg = 1 - K.round(K.clip(y_true, 0, 1))
    true_negatives = K.sum(y_neg * y_pred_neg)
    return true_negatives

'''
Counts the proportion of false positives to total negatives
'''
def false_positives(y_true, y_pred):
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_neg = 1 - K.round(K.clip(y_true, 0, 1))
    false_positives = K.sum(y_neg * y_pred_pos)
    return false_positives

'''
Counts the proportion of false negatives to total positives
'''
def false_negatives(y_true, y_pred):
    y_pred_neg = 1 - K.round(K.clip(y_pred, 0, 1))
    y_pos = K.round(K.clip(y_true, 0, 1))
    false_negatives = K.sum(y_pos * y_pred_neg)
    return false_negatives

'''
Counts the proportion of true positives to total actual positives
'''
def true_positive_rate(y_true, y_pred):
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_pos = K.round(K.clip(y_true, 0, 1))
    true_positives = K.sum(y_pos * y_pred_pos) / K.sum(y_pos + K.epsilon())
    return true_positives

'''
Counts the proportion of true negatives to total actual negatives
'''
def true_negative_rate(y_true, y_pred):
    y_pred_neg = 1 - K.round(K.clip(y_pred, 0, 1))
    y_neg = 1 - K.round(K.clip(y_true, 0, 1))
    true_negatives = K.sum(y_neg * y_pred_neg) / K.sum(y_neg + K.epsilon())
    return true_negatives

'''
Counts the proportion of false positives to total negatives
'''
def false_positive_rate(y_true, y_pred):
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_neg = 1 - K.round(K.clip(y_true, 0, 1))
    false_positives = K.sum(y_neg * y_pred_pos) / K.sum(y_neg + K.epsilon())
    return false_positives

'''
Counts the proportion of false negatives to total positives
'''
def false_negative_rate(y_true, y_pred):
    y_pred_neg = 1 - K.round(K.clip(y_pred, 0, 1))
    y_pos = K.round(K.clip(y_true, 0, 1))
    false_negatives = K.sum(y_pos * y_pred_neg) / K.sum(y_pos + K.epsilon())
    return false_negatives

'''
Not a metric and not currently used but it's a start if I eventually make a
custom loss function

Defining a weighted mean square error. Note that I am now using TensorFlow
specific functions so that is the required backend for this code to work...
it should be easy to translate this to other backends though (I just couldn't
figure out how to use Keras to do this).
'''
def my_loss_func(y_true, y_pred):
	print y_true
	print type(y_true)
	print y_true.eval(session=tf.Session())
	weighted_y_true = np.copy(y_true)
	weighted_y_true[weighted_y_true == 1] = 250000
	print weighted_y_true
	print type(weighted_y_true)
	weighted_y_pred = np.copy(y_pred)
	weighted_y_pred[weighted_y_pred == 1] = 250000
	# Weighted mean_absolute_error ?
	#return K.mean(K.abs(weighted_y_pred - weighted_y_true), axis=-1)

	# Weighted mean squared error?
	return K.mean(K.square(weighted_y_pred - y_pred), axis=-1)