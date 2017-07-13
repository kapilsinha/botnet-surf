'''
Following the tutorial at https://github.com/tensorflow/tensorflow/blob/
r1.2/tensorflow/examples/tutorials/mnist/fully_connected_feed.py
This will be an attempt to create a neural network with the graph statistics
at its time steps as inputs
'''
import tensorflow as tf

"""
Identifying malicious packets:
IP Address     Name     Infection time (Time of Day)  (Seconds since epoch)
147.32.84.165: SARUMAN  Infected at Aug 18 11:06:10 CEST 2011 -> 1313658370
147.32.84.191: SARUMAN1 Infected at Aug 18 11:06:32 CEST 2011 -> 1313658392
147.32.84.192: SARUMAN2 Infected at Aug 18 11:05:41 CEST 2011 -> 1313658341
147.32.84.193: SARUMAN3 Infected at Aug 18 11:06:52 CEST 2011 -> 1313658412
147.32.84.204: SARUMAN4 Infected at Aug 18 11:05:13 CEST 2011 -> 1313658313
147.32.84.205: SARUMAN5 Infected at Aug 18 11:07:15 CEST 2011 -> 1313658435
147.32.84.206: SARUMAN6 Infected at Aug 18 11:04:46 CEST 2011 -> 1313658286
147.32.84.207: SARUMAN7 Infected at Aug 18 11:04:20 CEST 2011 -> 1313658260
147.32.84.208: SARUMAN8 Infected at Aug 18 11:03:52 CEST 2011 -> 1313658232
147.32.84.209: SARUMAN9 Infected at Aug 18 11:03:05 CEST 2011 -> 1313658185
"""

VECTOR_SIZE = 10 # number of vertex characteristics in each vertex's vectors

def placeholder_inputs(batch_size, num_vertices):
   """
   Generate placeholder variables to represent the input tensors.
   These placeholders are used as inputs by the rest of the model building
   code and will be fed from the downloaded data in the .run() loop, below.
   Args:
     batch_size: The number of intervals (we will split all the intervals in
                 the pcap file into a training, validation, and test set)
     num_vertices: The number of vertices in each interval
   Returns:
     images_placeholder: Graphs placeholder.
     labels_placeholder: Labels placeholder.
   """
   graph_placeholder = tf.placeholder(tf.float32, shape=(num_vertices, VECTOR_SIZE))
   labels_placeholder = tf.placeholder(tf.int32, shape=(num_vertices))
   return graph_placeholder, labels_placeholder


def fill_feed_dict(data_set, graph_placeholder, labels_placeholder):
   """Fills the feed_dict for training the given step.
   A feed_dict takes the form of:
   feed_dict = {
       <placeholder>: <tensor of values to be passed for placeholder>,
       ....
   }
   Args:
     data_set: The set of graphs and labels
     graph_pl: The graph placeholder, from placeholder_inputs().
     label_pl: The labels placeholder, from placeholder_inputs().
   Returns:
     feed_dict: The feed dictionary mapping from placeholders to values.
   """
   graph_feed, labels_feed = .............
   feed_dict = {
       graph_placeholder: graph_feed,
       labels_placeholder: label_feed,
   }
   return feed_dict

def do_eval(sess, eval_correct, images_placeholder, labels_placeholder, data_set):
   """
   Runs one evaluation against the full epoch of data.
   Args:
     sess: The session in which the model has been trained.
     eval_correct: The Tensor that returns the number of correct predictions.
     images_placeholder: The images placeholder.
     labels_placeholder: The labels placeholder.
     data_set: The set of images and labels to evaluate, from
       input_data.read_data_sets().
   """
   # And run one epoch of eval.
   true_count = 0  # Counts the number of correct predictions.
   steps_per_epoch = data_set.num_examples // FLAGS.batch_size
   num_examples = steps_per_epoch * FLAGS.batch_size
   for step in xrange(steps_per_epoch):
      feed_dict = fill_feed_dict(data_set, graph_placeholder, labels_placeholder)
      true_count += sess.run(eval_correct, feed_dict=feed_dict)
   precision = float(true_count) / num_examples
   print('  Num examples: %d  Num correct: %d  Precision @ 1: %0.04f' %
         (num_examples, true_count, precision))


def run_training():
   """Train MNIST for a number of steps."""
   # Get the sets of images and labels for training, validation, and
   # test on MNIST.
   data_sets = input_data.read_data_sets(FLAGS.input_data_dir, FLAGS.fake_data)
 
   # Tell TensorFlow that the model will be built into the default Graph.
   with tf.Graph().as_default():
     # Generate placeholders for the images and labels.
     images_placeholder, labels_placeholder = placeholder_inputs(
         FLAGS.batch_size)
 
     # Build a Graph that computes predictions from the inference model.
     logits = mnist.inference(images_placeholder,
                              FLAGS.hidden1,
                              FLAGS.hidden2)
 
     # Add to the Graph the Ops for loss calculation.
     loss = mnist.loss(logits, labels_placeholder)
 
     # Add to the Graph the Ops that calculate and apply gradients.
     train_op = mnist.training(loss, FLAGS.learning_rate)
 
     # Add the Op to compare the logits to the labels during evaluation.
     eval_correct = mnist.evaluation(logits, labels_placeholder)
 
     # Build the summary Tensor based on the TF collection of Summaries.
     summary = tf.summary.merge_all()
 
     # Add the variable initializer Op.
     init = tf.global_variables_initializer()
 
     # Create a saver for writing training checkpoints.
     saver = tf.train.Saver()

     # Create a session for running Ops on the Graph.
     sess = tf.Session()
 
     # Instantiate a SummaryWriter to output summaries and the Graph.
     summary_writer = tf.summary.FileWriter(FLAGS.log_dir, sess.graph)
 
     # And then after everything is built:
 
     # Run the Op to initialize the variables.
     sess.run(init)
 
     # Start the training loop.
     for step in xrange(FLAGS.max_steps):
       start_time = time.time()
 
       # Fill a feed dictionary with the actual set of images and labels
       # for this particular training step.
       feed_dict = fill_feed_dict(data_sets.train, images_placeholder, labels_placeholder)

       # Run one step of the model.  The return values are the activations
       # from the `train_op` (which is discarded) and the `loss` Op.  To
       # inspect the values of your Ops or variables, you may include them
       # in the list passed to sess.run() and the value tensors will be
       # returned in the tuple from the call.
       _, loss_value = sess.run([train_op, loss],
                               feed_dict=feed_dict)

       duration = time.time() - start_time

       # Write the summaries and print an overview fairly often.
       if step % 100 == 0:
         # Print status to stdout.
         print('Step %d: loss = %.2f (%.3f sec)' % (step, loss_value, duration))
         # Update the events file.
         summary_str = sess.run(summary, feed_dict=feed_dict)
         summary_writer.add_summary(summary_str, step)
         summary_writer.flush()

       # Save a checkpoint and evaluate the model periodically.
       if (step + 1) % 1000 == 0 or (step + 1) == FLAGS.max_steps:
         checkpoint_file = os.path.join(FLAGS.log_dir, 'model.ckpt')
         saver.save(sess, checkpoint_file, global_step=step)
         # Evaluate against the training set.
         print('Training Data Eval:')
         do_eval(sess, eval_correct, images_placeholder, labels_placeholder, data_sets.train)
         # Evaluate against the validation set.
         print('Validation Data Eval:')
         do_eval(sess, eval_correct, images_placeholder, labels_placeholder, data_sets.validation)
         # Evaluate against the test set.
         print('Test Data Eval:')
         do_eval(sess, eval_correct, images_placeholder, labels_placeholder, data_sets.test)
